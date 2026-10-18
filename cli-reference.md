# NAME

wbind - bind mounts on MS Windows

# SYNOPSIS

wbind

```
[--help|-h]
[--unprivileged|-u]
[--version|-v]
[--whitelist|-w]
```

**Usage**:

```
wbind [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

**--unprivileged, -u**: use the wbindd helper service, so that mount, unmount and list need no elevation

**--version, -v**: print the version

**--whitelist, -w**: send a signed whitelist (see --whitelist-file and --sig-file of mount and unmount) to a helper service installed with --pubkey; implies --unprivileged


# COMMANDS

## mount

bind SOURCE (directory or file) at TARGET

**--help, -h**: show help

**--ro, -r**: mount read-only

**--sig-file**="": with --whitelist, read the whitelist's signature from `FILE` (- for stdin) (default: "wbind.sig.txt")

**--whitelist-file**="": with --whitelist, read the whitelist from `FILE` (- for stdin) (default: "wbind.whitelist.txt")

## unmount

remove the bind mount at TARGET

**--help, -h**: show help

**--sig-file**="": with --whitelist, read the whitelist's signature from `FILE` (- for stdin) (default: "wbind.sig.txt")

**--whitelist-file**="": with --whitelist, read the whitelist from `FILE` (- for stdin) (default: "wbind.whitelist.txt")

## list, ls

list all bind mounts, or only the one at TARGET

**--help, -h**: show help

**--noheadings, -n**: do not print a header line

## helperservice

manage the wbindd helper service, which serves --unprivileged requests

**--help, -h**: show help

### install

copy wbind.exe to the system directory, then install and start the helper service from there

**--group**="": let members of `GROUP` use the service; it is created if missing (default: wbind-users, created with Authenticated Users as member)

**--help, -h**: show help

**--pubkey**="": copy the public key `FILE` (see 'wbind sig keygen') next to wbind.exe and accept only mounts allowed by a whitelist signed with its private key

**--unmount-requires-whitelist**: with --pubkey, accept only unmounts allowed by the whitelist too (by default, anyone may unmount anything)

### uninstall

stop and remove the helper service

**--help, -h**: show help

## sig

generate keys, and sign and test whitelists for a helper service installed with --pubkey

**--help, -h**: show help

### keygen

create a new ML-DSA key pair

**--help, -h**: show help

**--private**="": write the private key to `FILE`, which must not exist (default: "wbind.privkey.txt")

**--public**="": write the public key to `FILE`, which must not exist (default: "wbind.pubkey.txt")

### example

write an example whitelist that shows all features, with all rules commented out

**--force**: overwrite the --output file if it exists

**--help, -h**: show help

**--output**="": write to `FILE`, which must not exist (default: "wbind.whitelist.txt")

### sign

sign a whitelist with a private key

**--help, -h**: show help

**--key**="": read the private key from `FILE` (- for stdin) (default: "wbind.privkey.txt")

**--output**="": write the signature to `FILE` (- for stdout) (default: "wbind.sig.txt")

**--whitelist-file**="": read the whitelist from `FILE` (- for stdin) (default: "wbind.whitelist.txt")

### test

check whether a whitelist allows the current user to bind SOURCE at TARGET (does not check a signature)

**--help, -h**: show help

**--ro, -r**: check a read-only mount

**--whitelist-file**="": read the whitelist from `FILE` (- for stdin) (default: "wbind.whitelist.txt")

## docs

show auto-generated cli reference docs

**--help, -h**: show help

**--output**="": write to `FILE` instead of stdout
