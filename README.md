# wbind - bind mounts on MS Windows

![wbind](wbind.png)

Modern MS Windows supports true, Unix-style bind mounts. The `wbind` CLI tools makes it easy to create, remove and list them. This lets you make a file or directory from another local or UNC path virtually appear at a different local path.

A thin CLI tool around [microsoft/go-winio](https://github.com/microsoft/go-winio)'s [`bindfilter`](https://pkg.go.dev/github.com/Microsoft/go-winio/pkg/bindfilter) package, which provides bindings to the win32 [bindflt](https://learn.microsoft.com/en-us/windows/win32/bindlink/) api.

Needs Win10 1809 or greater (any Win11 works) or Windows Server 2019 or greater. (Windows Server 2016 is the only still supported version of Windows that is too old). Needs to run elevated / with admin privs. (Created bind mounts are accessible for all users, no admin privs needed).

Bind mounts are in-memory / ephemeral and will disappear at reboot (or when unmounted).

## Install
Download binaries from [releases](https://github.com/christian-korneck/wbind/releases/latest).

## Usage

### Mount a file or dir
```
wbind mount <source> <target>
```

(you can also mount read-only with: `wbind mount --ro <source> <target>`)

### Umount a file or dir
```
wbind unmount <source> <target>
```

### List binds
```
wbind ls
```

You can also "overmount", mount a file into an already mounted dir and mount from a UNC path (smb share) to a local destination. Basically anything needed for complex "composing" of a virtual target.

For the full usage see the auto-generated [CLI reference docs](cli-reference.md).

## Demo

### example: bind-mount and un-mount a directory (files work the same way)

```powershell
# create/mount
PS> dir c:\demo
dir : Cannot find path 'C:\demo' because it does not exist.

PS> wbind.exe mount c:\windows\system32\drivers\etc c:\demo
PS> dir c:\demo
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/24/2026   5:33 PM           2132 hosts
-a----         9/24/2026   5:36 PM            629 hosts.ics
...

# list all active binds
PS> wbind.exe ls
TARGET   SOURCE                           OPTIONS
C:\demo  C:\Windows\System32\drivers\etc  rw

# umount
PS> wbind.exe unmount c:\demo
```

## Use without elevation (via an optional helper service)

To optionally allow unprivileged users to mount/unmount/list bind mounts, `wbind` offters an optional helper service.

You install it once with admin privileges with:

```
wbind helperservice install
```

The helper service runs as a privileged windows service (`wbindd`) in the background and and from then on unprivileged users can run any wbind command against it with the `-u` / `--unprivileged` flag.
 
Example:

```
wbind -u ls
wbind -u mount c:\source c:\dest
wbind -u unmount c:\dest
```

(After installation users might need to re-login to Windows once).

The connection between client and server happens over a named pipe (`\\.\pipe\wbindd`). Access to the pipe is restricted to a specific group. By default the service installation creates a local group `wbind-users` and adds the `Authenticated Users` group as its member, so all users can access it.

You can alternatively define your own group. It will be created if it doesn't exist yet (and no members will be added - this is up to you):

```
wbind helperservice install [--group <name>]
```

To remove the service, run `wbind helperservice uninstall` from an elevated shell. The group is kept.

Notes:
- Using the helperservice has security implications and comes with risks
- expect problems with the helper service and UNC paths (smb shares): With the helperservice you can only uses a SOURCE path that the user that runs the service (by default: the local `SYSTEM` user) has access to. So you can't use a UNC path (smb share) as source to which only the user that runs `wbind -u mount` has access to, but not the user that runs the service. To work around this you can give the user that runs the service access to the respective UNC path / smb share.


## Optionally restrict the helper service with signed whitelists [EXPERIMENTAL FEATURE]

There's also an optional additional security mode for the helper service that requires the calling user to submit a signed whitelist.

In this mode, the helper service holds a public key file and only accepts mount requests from unprivileged users if the source/destination path matches a source/destination pattern from a whitelist. The whitelist gets submitted by the user, too - but the whitelist needs to be signed and the signature also needs to be passed.

This is what a mount call from an unprivileged user looks like:

```
wbind -w mount --whitelist-file wl.txt --sig-file sig.txt c:\source c:\target
```

This allows someone to place the whitelist and its signature for example as part of a script (inline or as files next to it), etc.

Paths in whitelists are written in GLOB syntax (.gitignore like syntax, so various types of wildcards work) and support special windows variables like %userprofile% (resolves to the calling user's user profile and the helper service tries to prevent that the user could fake his identity to mess with foreign user profiles) or %programfiles% (which works no matter of the windows installation language).

See the [separate docs for the signed whitelist feature](README-signed-whitelists.md) and the [example whitelist](wbind.whitelist.example.txt).


## Notes

- the SOURCE path must exist and can be a directory or a file. Local or on a UNC path (smb share).
- the TARGET must be on a local volume (but UNC paths / smb shares do NOT work as target)
- the TARGET path does not need to exist. The bind filter virtually "projects" it while the mount exists and it disappears again after an `unmount` (or reboot). However, the TARGET path's parent directory must already exist.
- If the TARGET path already exists, its own contents are hidden while "overmounted" and come back after an `unmount` (or reboot).
- bind mounts are system-wide and in memory. They do not persist a reboot.
- a read-only mount rejects writes and deletions with "access denied".

