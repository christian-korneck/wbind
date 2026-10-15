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


## Notes

- the SOURCE path must exist and can be a directory or a file. Local or on a UNC path (smb share).
- the TARGET must be on a local volume (but UNC paths / smb shares do NOT work as target)
- the TARGET path does not need to exist. The bind filter virtually "projects" it while the mount exists and it disappears again after an `unmount` (or reboot). However, the TARGET path's parent directory must already exist.
- If the TARGET path already exists, its own contents are hidden while "overmounted" and come back after an `unmount` (or reboot).
- bind mounts are system-wide and in memory. They do not persist a reboot.
- a read-only mount rejects writes and deletions with "access denied".

