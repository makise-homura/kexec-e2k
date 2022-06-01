# Build

```
meson build
cd build
ninja
```

You may specify `-Dstatic=enabled` if you wish to build static binary.

## Build requirements

* `<limits.h>` should have `PATH_MAX` defined.
* `libpci` should be available to meson to enable bridge reset (but project is still buildable without it, yet you will not be able to reset PCI bridge in this case).

# Usage

```
kexec-lintel [OPTIONS] [FILE]
```

* `FILE`: Lintel file to start (may be a plain lintel starter, BCD image, or a BCD image with kexec jumper).
Wildcards are supported (to prevent shell expansion, put the argument in quotes).
Only one file should fit the pattern then.
If not specified, `/opt/mcst/lintel/bin/lintel_*.disk` is loaded.
Specify `-` to load lintel from standard input.

Options:

* `-h`, `--help`: Show help and exit
* `-t <N>`, `--tty <N>`: Reset framebuffer device associated with ttyN instead of currently active one (has no effect if `-b`, or all two or three of `-M`, `-P`, and, if supported, `-B` are given)
* `-d <DEVNAME>`: Avoid asking for boot drive and boot guest OS from `DEVNAME` (e.g. `/dev/sdc`) by default
* `-T`: Prohibit lintel to react at any keypress to perform a controlled trusted boot (has an effect only if `-d` is given)
* `-n`: Don't check that boot disk AHCI controller is on node 0 (has an effect only if -d is given)
* `-m`: Don't check for unmounted filesystems and don't mount them
* `-i`: Don't check that IOMMU is off
* `-r`: Don't check current runlevel
* `-b`: Don't reset current framebuffer device
* `-f`: Don't sync, flush, and remount-read-only filesystems
* `-v`: Don't pass current video adapter id to lintel and make it use the one specified in NVRAM
* `-V`: Don't unbind currently active vtconsole (has no effect if `-b` is given)
* `-M`: Don't unload module bound to PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-P`: Don't remove PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-B`: Don't reset PCI bridge associtated with PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-x`: Don't perform actual kexec_lintel but everything preceeding it

Option `-B` is supported only if built with `libpci`; if not, option is silently skipped and binary acts as if it is always enabled.

# Limitations

* You should be in runlevel 1 to run this (but you can disable this check by `-r`).
* You should have IOMMU disabled (but you can disable this check by `-i`).
* You should have the same lintel BCD image written on some disk (unless supplied image contains kexec jumper).
* No other disks should contain lintel except one mentioned above (unless supplied image contains kexec jumper).
* All Lintel hadrware limitations (e.g. SATA controller 0, etc.) apply.
