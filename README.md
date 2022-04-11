# Build

```
meson build
cd build
ninja
```

# Usage

```
kexec-lintel [ [--tty <N>] <path> | -h | --help ]
```

`<N>`: active tty number (default is `1`)
`<path>`: path to lintel file (default is `/opt/mcst/lintel/bin/lintel_e8c.disk`)
`-h` or `--help`: Print help

# Limitations

* You should be in runlevel 1 to run this.
* You should have the same lintel BCD image written on some disk.
* No other disks should contain lintel.
* All Lintel hadrware limitations (e.g. SATA controller 0, etc.) apply.
