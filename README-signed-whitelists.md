# signed whitelists feature - docs [EXPERIMENTAL FEATURE]

Optionally restrict the helper service with signed whitelists.

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