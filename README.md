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

### Use without elevation (via an optional helper service)

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


### Optionally restrict the helper service with signed whitelists [EXPERIMENTAL FEATURE]

Signed whitelists limit what unprivileged users can mount through the helper service. For this, the CLI has a `-w` / `--whitelist` mode, which always connects to the helper service. The service is in a mode in which it rejects any non-whitelisted request. The user passes a whitelist and its signature along with each mount (`wbind -w mount --whitelist-file LIST --sig-file SIG SOURCE TARGET`). The service holds only the public key. So a whitelist and its signature can be packaged for example alongside a script or [rez](https://github.com/AcademySoftwareFoundation/rez)-style package that needs it, and new whitelists need no change to the service installation. (What needs to be kept secret is the privat key to sign new whitelists).

Demo:

```powershell
# admin: create a key pair, install the helper service with the public key
PS> wbind sig keygen
PS> wbind helperservice install --pubkey wbind.pubkey.txt

# admin: allow mounting the etc folder at c:\demo, then sign
PS> Set-Content wbind.whitelist.txt 'C:/Windows/System32/drivers/etc | C:/demo'
PS> wbind sig sign

# user (no admin rights): mount with wbind.whitelist.txt and wbind.sig.txt from the current dir
PS> wbind -w mount c:\windows\system32\drivers\etc c:\demo
PS> wbind -u ls
TARGET   SOURCE                           OPTIONS
C:\demo  C:\Windows\System32\drivers\etc  rw

# user: a target the whitelist doesn't allow
PS> wbind -w mount c:\windows\system32\drivers\etc c:\demo2
wbind: mount: C:\demo2: source C:\Windows\System32\drivers\etc: not allowed by the whitelist
```

Keep the private key secret: Whoever has it can sign a whitelist that allows any mount.

Unmounting stays open to all users of the service. The opposite can be fored at install with `wbind helperservice install --unmount-requires-whitelist`.

#### Writing a whitelist

As admin, start from the template, test, then sign:

```
wbind sig example                    # creates wbind.whitelist.txt with commented-out examples
notepad wbind.whitelist.txt          # write the rules you want to allow
wbind sig test c:\source c:\dest     # optional: validate which rule from the whitelist allows this mount
wbind sig sign                       # signs with wbind.privkey.txt, creates wbind.sig.txt
```

Ship `wbind.whitelist.txt` and `wbind.sig.txt`, for example next to the script that mounts.

#### Mounting with a whitelist

`-w` connects to the helper service like `-u`. Without `--whitelist-file` and `--sig-file`, wbind reads `wbind.whitelist.txt` and `wbind.sig.txt` from the current directory. `-` as file name reads stdin.

```
wbind -w mount c:\source c:\dest
wbind -w mount --whitelist-file C:\scripts\wbind.whitelist.txt --sig-file C:\scripts\wbind.sig.txt c:\source c:\dest
```

#### Whitelist format - basics

[Doublestar](https://github.com/bmatcuk/doublestar) glob syntax (similar to `.gitignore`), case-insensitive, with `/` as path separator (`C:/data`, `//server/share`) and `\` as escape (`\%`, `\[`). These special variables get resolved automatically:

- `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`: folders of the user who runs `wbind -w` (the helper service determines the user by itself)
- `%USERNAME%`, `%USERDOMAIN%`: that user's account name and domain
- `%PROGRAMFILES%`, `%PROGRAMFILES(X86)%`, `%COMMONPROGRAMFILES%`, `%COMMONPROGRAMFILES(X86)%`
- `%PROGRAMDATA%`, `%ALLUSERSPROFILE%`, `%PUBLIC%`
- `%SYSTEMDRIVE%`, `%SYSTEMROOT%`, `%WINDIR%`

The variables are looked up on the machine, not taken from environment variables, so they fit any install drive and Windows language. The calling processes user identity gets verified, so that userprofile related paths match the calling user (a user can't do things outside its own userprofile).

Check [the example whitelist](wbind.whitelist.example.txt), the file `wbind sig example` creates, which shows most features.

#### whitelist format - simple examples

Plain text with one rule per line: `SOURCE | TARGET`. Add `| ro` to allow only read-only mounts (`wbind mount --ro`); without it, a rule allows read-only and read-write mounts. Lines starting with `#` are comments.

Examples:

```
# anything from your own profile, at any folder directly under %USERPROFILE%/mnt
%USERPROFILE%/** | %USERPROFILE%/mnt/*

# a shared tools folder as plugin folder, read-only
D:/shared/tools | %PROGRAMFILES%/MyApp/plugins | ro

# folders of a file share, into your local app data
//fileserver/share/* | %LOCALAPPDATA%/cache/*
```


#### whitelist format - good to know:

- Always put `/` after a path variable. `%USERPROFILE%*` would also match `C:/Users/bobby`.
- `%APPDATA%` and `%LOCALAPPDATA%` are always `<profile>/AppData/Roaming` and `<profile>/AppData/Local`. Redirected folders are ignored, because users can redirect them anywhere.
- `%USERNAME%` alone doesn't tell a local user from a domain user of the same name. Combine it with `%USERDOMAIN%`.
- Paths are normalized before matching: `.` and `..` are resolved, and so are symlinks, junctions and 8.3 short names. Rules are not, so write them as plain paths; `.` and `..` in a rule are rejected.

## Notes

- the SOURCE path must exist and can be a directory or a file. Local or on a UNC path (smb share).
- the TARGET must be on a local volume (but UNC paths / smb shares do NOT work as target)
- the TARGET path does not need to exist. The bind filter virtually "projects" it while the mount exists and it disappears again after an `unmount` (or reboot). However, the TARGET path's parent directory must already exist.
- If the TARGET path already exists, its own contents are hidden while "overmounted" and come back after an `unmount` (or reboot).
- bind mounts are system-wide and in memory. They do not persist a reboot.
- a read-only mount rejects writes and deletions with "access denied".

