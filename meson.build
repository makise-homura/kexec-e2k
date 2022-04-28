project('kexec-lintel', 'c', meson_version: '>=0.50.0')
cc = meson.get_compiler('c')
cc.has_header_symbol('limits.h', 'PATH_MAX', required : true)

if not cc.has_function('strchrnul', prefix: '#include <string.h>', args: '-D_GNU_SOURCE')
    add_global_arguments('-DNO_STRCHRNUL', language : 'c')
endif

if not meson.is_cross_build()
    # Assume sizes are ok when cross compiling, because we are unable to check it
    sz_pfile = cc.sizeof('FILE*', prefix: '#include <stdio.h>')
    sz_plops = cc.sizeof('struct lintelops*', prefix: '#include "kexec-lintel.c"', args: '-DAS_INCLUDE', include_directories: include_directories('.'))
    if (sz_pfile == -1) or (sz_plops == -1)
        error('Can not check sizes of FILE* and struct lintelops*.')
    endif
    if not (sz_pfile == sz_plops)
        error('Your platform has different pointer sizes of FILE and structs, can not build here.')
    endif
endif

static = get_option('static').enabled()

if static
    static_arg = [ '-static' ]
else
    static_arg = []
endif

libpci_dep = dependency('libpci', required : false, static: static)
if not libpci_dep.found() or not cc.links('int main(void) {}', dependencies: libpci_dep, args: static_arg)
    add_global_arguments('-DNO_BRIDGE_RESET', language : 'c')
    libpci = []
else
    libpci = [ libpci_dep ]
endif

executable('kexec-lintel', 'kexec-lintel.c', dependencies: libpci, link_args: static_arg)
