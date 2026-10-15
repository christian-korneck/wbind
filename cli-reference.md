# NAME

wbind - bind mounts on MS Windows

# SYNOPSIS

wbind

```
[--help|-h]
[--version|-v]
```

**Usage**:

```
wbind [GLOBAL OPTIONS] [command [COMMAND OPTIONS]] [ARGUMENTS...]
```

# GLOBAL OPTIONS

**--help, -h**: show help

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

## docs

show auto-generated cli reference docs

**--help, -h**: show help

**--output**="": write to `FILE` instead of stdout
