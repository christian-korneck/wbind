# NAME

wbind - bind mounts on MS Windows

# SYNOPSIS

wbind

```
[--help|-h]
[--unprivileged|-u]
[--version|-v]
```

**Usage**:

```
wbind [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

**--unprivileged, -u**: use the wbindd helper service, so that mount, unmount and list need no elevation

**--version, -v**: print the version


# COMMANDS

## mount

bind SOURCE (directory or file) at TARGET

**--help, -h**: show help

**--ro, -r**: mount read-only

## unmount

remove the bind mount at TARGET

**--help, -h**: show help

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

### uninstall

stop and remove the helper service

**--help, -h**: show help

## docs

show auto-generated cli reference docs

**--help, -h**: show help

**--output**="": write to `FILE` instead of stdout
