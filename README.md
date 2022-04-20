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

* `FILE`: Lintel file to start (may be a plain lintel starter, BCD image, or a BCD image with kexec jumper). If not specified, `/opt/mcst/lintel/bin/lintel_e8c.disk` is loaded.

Options:

* `-h`, `--help`: Show help and exit
* `-t <N>`, `--tty <N>`: Reset framebuffer device associated with ttyN instead of tty1 (has no effect if `-b`, or all three of `-M`, `-P`, and `-B` (if supported) are given)
* `-i`: Don't check that IOMMU is off
* `-r`: Don't check current runlevel
* `-b`: Don't reset current framebuffer device
* `-f`: Don't sync, flush, and remount-read-only filesystems
* `-V`: Don't unbing currently active vtconsole (has no effect if `-b` is given)
* `-M`: Don't unload module bound to PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-P`: Don't remove PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-B`: Don't reset PCI bridge associtated with PCI Express device implementing current framebuffer (has no effect if `-b` is given)

Option `-B` is available only if built with `libpci`; if not, option is not recognized as valid and binary acts as if it is always enabled.

# Limitations

* You should be in runlevel 1 to run this (but you can disable this check by `-r`).
* You should have IOMMU disabled (but you can disable this check by `-i`).
* You should have the same lintel BCD image written on some disk (unless supplied image contains kexec jumper).
* No other disks should contain lintel except one mentioned above (unless supplied image contains kexec jumper).
* All Lintel hadrware limitations (e.g. SATA controller 0, etc.) apply.
