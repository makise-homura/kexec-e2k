project('kexec-lintel', 'c', meson_version: '>=0.50.0')
cc = meson.get_compiler('c')
cc.has_header_symbol('limits.h', 'PATH_MAX', required : true)

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
