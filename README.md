# Build

## General build flow

```
meson build
cd build
ninja
ninja install
```

## Options

* You may specify `-Dprefix=<PREFIX>` to override default install prefix. Resulting binary will be installed to `<PREFIX>/bin/kexec-e2k`.
* You may specify `-Dstatic=enabled` if you wish to build static binary.
* You may set `-Duse_kernel_hdr=false` if you don't want to use installed kernel headers to determine kernel command line length.
* You may specify path to kernel headers include directory by an option like `-Dkernel_hdr_dir=/usr/src/linux-headers-5.4.0-3.19-common/include`, if you have an alternative path for common kernel headers. Has no effect if `-Duse_kernel_hdr=false` is specified. Otherwise, it is mandatory while cross building.
* You may explicitly set kernel command line length by an option like `-Dcmdline_length=1024`. This value will be used if kernel headers not found or `-Duse_kernel_hdr=false` is specified. Default value is 512.

## Build requirements

* `<limits.h>` should have `PATH_MAX` defined.
* Unless `-Duse_kernel_hdr=false` is specified, you should have common kernel headers installed (specifically, `uapi/asm-generic/setup.h` header with `COMMAND_LINE_SIZE` defined).

# Usage

```
kexec-e2k [OPTIONS] [FILE]
```

* `FILE`: File to start (may be a plain lintel starter or kernel image, lintel BCD image, or a lintel BCD image with kexec jumper).
Wildcards are supported (to prevent shell expansion, put the argument in quotes).
Only one file should fit the pattern then.
If not specified, `/opt/mcst/lintel/bin/lintel_*.disk` is loaded.
Specify `-` to load a file from standard input.

Options:

* `--version`: Show version and exit
* `-h`, `--help`: Show help and exit
* `-t <N>`, `--tty <N>`: Reset framebuffer device associated with `tty<N>` instead of currently active one (has no effect if `-b`, or all two or three of `-M` and `-P` are given)
* `-e <N>`: Allow only `<N>` network adapters\n");
* `-E <TYPE>`: Set network adapter type to `<TYPE>` (supported types: `Intel`, `PCNet`, `Elbrus`)
* `-m`: Don't check for unmounted filesystems and don't mount them
* `-i`: Ignored (for backwards compatibility)
* `-r`: Don't check current runlevel
* `-X`: Don't check if X is started
* `-b`: Don't reset current framebuffer device
* `-f`: Don't sync, flush, and remount-read-only filesystems
* `-V`: Don't unbind currently active vtconsole (has no effect if `-b` is given)
* `-M`: Don't unload module bound to PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-P`: Don't remove PCI Express device implementing current framebuffer (has no effect if `-b` is given)
* `-B`: Ignored (for backwards compatibility)
* `-x`: Don't perform actual kexec call, but everything preceeding it

When starting kernel image:

* `-I <FILE>`: Use `<FILE>` as initrd image (no initrd image is passed if not specified)
* `-c <CMDLINE>`: Pass `<CMDLINE>` as new kernel command line (one of currently loaded kernel is passed if neither `-c` nor `-a` specified)
* `-a <CMDLINE>`: Add `<CMDLINE>` to one of currently loaded kernel to produce new kernel command line

When starting lintel image:

* `-l`: Treat non-BCD file as a lintel starter, not kernel image
* `-d <DEVNAME>`: Avoid asking for boot drive and boot guest OS from `<DEVNAME>` (e.g. `/dev/sdc`) by default
* `-N <FILE>`: Use `<FILE>` as NVRAM image (if not specified, lintel will read actual NVRAM). Create it by calling `dd if=/dev/nvram of=<FILE> bs=256 skip=1 count=3`
* `-T`: Prohibit lintel to react at any keypress to perform a controlled trusted boot (has an effect only if `-d` is given)
* `-n`: Don't check that boot disk AHCI controller is on node 0 (has an effect only if `-d` is given)
* `-v`: Don't pass current video adapter id to lintel and make it use the one configured in NVRAM

# Limitations

* You should be in runlevel 1 to run this (but you can disable this check by `-r`, specifically when your OS does not support runlevels).
* You should not be running X, it may interfere with framebuffer usage (but you can disable this check by `-X`).
* You may consider having IOMMU disabled in case of loading outdated lintel images. As long as you use modern kernel or lintel image, this is not required (and no check for IOMMU performed, as in earlier versions of this tool).
* If booting outdated lintel withot kexec jumper, you should have the same lintel BCD image written on one, and only one disk in the system.
* If booting lintel, all its hardware limitations (e.g. SATA controller 0, etc.) may apply.
