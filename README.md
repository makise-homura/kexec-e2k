# Build

```
meson build
cd build
ninja
```

## Build requirements

* `<limits.h>` should have `PATH_MAX` defined.
* `libpci` should be available to meson.

## Binaries

It will produce four binaries:

* `kexec-lintel`: just a normal kexec-lintel binary.
* `kexec-lintel-nofbreset`: the one which does not reset PCI device of the active framebuffer, so lintel would crash if framebuffer device is different from VGA16.
* `kexec-lintel-noiommucheck`: the one which does not check that IOMMU is off, so lintel would crash when it is on.
* `kexec-lintel-noiommucheck-nofbreset`: a combination of the two above.

# Usage

```
kexec-lintel [ [--tty <N>] <path> | -h | --help ]
```

* `<N>`: active tty number (default is `1`)
* `<path>`: path to lintel file (default is `/opt/mcst/lintel/bin/lintel_e8c.disk`)
* `-h` or `--help`: Print help

# Limitations

* You should be in runlevel 1 to run this.
* You should have IOMMU disabled.
* You should have the same lintel BCD image written on some disk.
* No other disks should contain lintel.
* All Lintel hadrware limitations (e.g. SATA controller 0, etc.) apply.
