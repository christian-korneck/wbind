//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName  = "wbindd"
	defaultGroup = "wbind-users"
)

// pipeName is where the helper service serves its API. Tests change it.
var pipeName = `\\.\pipe\` + serviceName

func installAction(_ context.Context, cmd *cli.Command) error {
	if err := installService(cmd.String("group")); err != nil {
		return fmt.Errorf("helperservice install: %w", err)
	}
	return nil
}

func uninstallAction(context.Context, *cli.Command) error {
	if err := uninstallService(); err != nil {
		return fmt.Errorf("helperservice uninstall: %w", err)
	}
	return nil
}

// daemonAction runs the helper service. The SCM starts it; run from a
// console, it serves in the foreground until Ctrl+C.
func daemonAction(_ context.Context, cmd *cli.Command) error {
	s := service{group: cmd.String("group")}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if !isService {
		err = debug.Run(serviceName, s)
	} else {
		err = svc.Run(serviceName, s)
	}
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	return nil
}

// installService creates group unless it exists (the default group with
// Authenticated Users as its member), copies wbind.exe to the system
// directory and installs and starts the helper service from there. The
// service runs as LocalSystem and starts at boot.
func installService(group string) error {
	if err := requireElevated(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	// Check first, so that a reinstall cannot copy over the binary of an
	// installed service.
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return windows.ERROR_SERVICE_EXISTS
	}

	var members []*windows.SID
	if group == "" {
		au, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
		if err != nil {
			return err
		}
		group, members = defaultGroup, []*windows.SID{au}
	}
	if err := ensureGroup(group, members...); err != nil {
		return err
	}

	exe, err := installedExe()
	if err != nil {
		return err
	}
	if err := copySelf(exe); err != nil {
		return err
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "wbind helper service",
		Description: "Lets members of " + group + " manage bind mounts with 'wbind --unprivileged'.",
		StartType:   mgr.StartAutomatic,
	}, "daemon", "--group", group)
	if err != nil {
		os.Remove(exe) // undo the copy
		return err
	}
	defer s.Close()
	if err := setRecovery(s); err != nil {
		s.Delete()
		os.Remove(exe)
		return err
	}

	if err := s.Start(); err != nil {
		return err
	}
	st, err := waitFor(s, svc.Running)
	if err == nil && st.State != svc.Running {
		err = fmt.Errorf("service stopped: %w", windows.Errno(st.Win32ExitCode))
	}
	return err
}

// setRecovery makes the SCM restart s after a failure like dockerd does:
// twice after 15s, counting failures over 24h. By default the SCM only
// recovers from crashes. The service, like dockerd, reports its own
// failures (such as a group lookup at boot before the domain controller is
// reachable) as a stop with an error exit code, so recovery is enabled for
// those too, which dockerd does not do. A normal stop exits with 0.
func setRecovery(s *mgr.Service) error {
	err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.NoAction},
	}, uint32(24*time.Hour/time.Second))
	if err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// uninstallService stops and removes the helper service and its copy of
// wbind.exe. It leaves the group alone, which may be in use elsewhere.
func uninstallService() error {
	if err := requireElevated(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := stopService(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return err
	}
	exe, err := installedExe()
	if err != nil {
		return err
	}
	return removeExe(exe)
}

// stopService stops s and waits up to 10s for its process to exit, which
// releases the executable.
func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil || st.ProcessId == 0 {
		return err
	}
	p, err := windows.OpenProcess(windows.SYNCHRONIZE, false, st.ProcessId)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p)
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	ev, err := windows.WaitForSingleObject(p, 10_000)
	if err == nil && ev != windows.WAIT_OBJECT_0 {
		err = errors.New("timed out waiting for the service to stop")
	}
	return err
}

// installedExe is where install puts wbind.exe: the system directory, which
// is on PATH and only administrators can write to. GetSystemDirectory,
// unlike %SystemRoot%, does not depend on the caller's environment.
func installedExe() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wbind.exe"), nil
}

// copySelf copies the running executable to dst, unless it is dst.
func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if si, err := in.Stat(); err == nil {
		if di, err := os.Stat(dst); err == nil && os.SameFile(si, di) {
			return nil
		}
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// removeExe deletes exe. Windows refuses that while exe runs, as when
// uninstall runs from it (wbind on PATH). Then exe gets renamed, which frees
// its name for a reinstall, and the renamed file is deleted at the next
// restart.
func removeExe(exe string) error {
	err := os.Remove(exe)
	switch {
	case err == nil, errors.Is(err, os.ErrNotExist):
		return nil
	case !errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return err
	}
	old := fmt.Sprintf("%s.%d.delete", exe, os.Getpid())
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(old)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

// waitFor waits up to 10s for s to reach state, or to stop.
func waitFor(s *mgr.Service, state svc.State) (svc.Status, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := s.Query()
		if err != nil || st.State == state || st.State == svc.Stopped {
			return st, err
		}
		if time.Now().After(deadline) {
			return st, errors.New("timed out waiting for the service")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// service is the helper service: it serves newHandler on pipeName.
type service struct {
	group string // members may connect, besides SYSTEM and elevated admins
}

func (s service) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	l, err := listen(s.group)
	if err != nil {
		return exitCode(err)
	}
	srv := &http.Server{Handler: newHandler()}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				srv.Shutdown(context.Background())
				return false, 0
			}
		case err := <-done:
			return exitCode(err)
		}
	}
}

// exitCode turns err into the exit code of Execute. The SCM logs it to the
// System event log.
func exitCode(err error) (svcSpecific bool, code uint32) {
	if errno, ok := errors.AsType[windows.Errno](err); ok {
		return false, uint32(errno)
	}
	return true, 1
}

// listen creates the API pipe. Only SYSTEM, elevated administrators and
// the members of group (if not "") may connect. The Administrators SID is
// deny-only in UAC-filtered tokens, so unelevated admins need the group.
// Like dockerd, the group only gets read and write, which is all that
// go-winio's DialPipe asks for.
func listen(group string) (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if group != "" {
		sid, _, _, err := windows.LookupSID("", group)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group, err)
		}
		sddl += "(A;;GRGW;;;" + sid.String() + ")"
	}
	return winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: sddl})
}

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupAdd        = netapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
)

// ensureGroup creates the local group name with members, unless an account
// of that name exists already, which it then leaves unchanged.
func ensureGroup(name string, members ...*windows.SID) error {
	if _, _, _, err := windows.LookupSID("", name); !errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return err
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	comment, err := windows.UTF16PtrFromString("Members can use the wbind helper service (wbind --unprivileged).")
	if err != nil {
		return err
	}
	info := struct{ name, comment *uint16 }{n, comment} // LOCALGROUP_INFO_1
	if r, _, _ := procNetLocalGroupAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0); r != 0 {
		return fmt.Errorf("creating group %s: %w", name, windows.Errno(r))
	}
	for _, sid := range members {
		// A LOCALGROUP_MEMBERS_INFO_0 is just a PSID.
		if r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(n)), 0, uintptr(unsafe.Pointer(&sid)), 1); r != 0 {
			return fmt.Errorf("adding %s to group %s: %w", sid, name, windows.Errno(r))
		}
	}
	return nil
}
