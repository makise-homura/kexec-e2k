project('kexec-lintel', 'c')
meson.get_compiler('c').has_header_symbol('limits.h', 'PATH_MAX', required : true)
executable('kexec-lintel', 'kexec-lintel.c', dependencies: dependency('libpci'))
