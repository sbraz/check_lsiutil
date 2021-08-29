# Introduction

This plugin can be used to check physical error counters for LSI HBAs.
It keeps track of previous values to raise errors when an error counter sees an increment.

# Requirements

The script requires:
* Python 3.7 or newer
* lsiutil (1.70 or newer is required to support MPT3 devices)
* [`nagiosplugin`](https://nagiosplugin.readthedocs.io) version 1.2.4 or newer
* util-linux 2.27 or newer (lsblk with JSON output support)
* lsscsi
* sudo and access to `lsiutil` commands
* read-write access to `/var/tmp/` (where the state file is created)

# Security

In order to limit the attack surface as much as possible, it is recommended to
only grant sudo access to the required `lsiutil` commands.

For example, create `/etc/sudoders.d/check_lsiutil` containing:
```
icinga ALL=(ALL) NOPASSWD: /usr/bin/lsiutil 0
icinga ALL=(ALL) NOPASSWD: /usr/bin/lsiutil -p [0-9] -a 16\,20\,12\,0\,0
icinga ALL=(ALL) NOPASSWD: /usr/bin/lsiutil -p [0-9][0-9] -a 16\,20\,12\,0\,0
```

# Integration with Icinga

An Icinga `CheckCommand` can be defined with:
```
object CheckCommand "lsiutil" {
  command = [PluginDir + "/check_lsiutil.py"]
  arguments = {
    "--max-attempts" = "$max_check_attempts$"
  }
}
```
