project('kexec-lintel', 'c', meson_version: '>=0.50.0')
cc = meson.get_compiler('c')
cc.has_header_symbol('limits.h', 'PATH_MAX', required : true)

static = get_option('static').enabled()

if static
    static_arg = [ '-static' ]
else
    static_arg = []
endif

if get_option('build_generic').enabled() or get_option('build_noiommucheck').enabled()
    libpci_dep = dependency('libpci', required : false, static: static)
    if not libpci_dep.found() or not cc.links('int main(void) {}', dependencies: libpci_dep, args: static_arg)
        add_global_arguments('-DNO_BRIDGE_RESET', language : 'c')
        libpci = []
    else
        libpci = [ libpci_dep ]
    endif
endif

if get_option('build_generic').enabled()
    executable('kexec-lintel', [ 'kexec-lintel.c', 'fbreset.c', 'iommucheck.c' ], dependencies: libpci, link_args: static_arg)
endif

if get_option('build_nofbreset').enabled()
    executable('kexec-lintel-nofbreset', [ 'kexec-lintel.c', 'iommucheck.c' ], c_args: [ '-DNO_FBRESET' ], link_args: static_arg)
endif

if get_option('build_noiommucheck').enabled()
    executable('kexec-lintel-noiommucheck', [ 'kexec-lintel.c', 'fbreset.c' ], dependencies: libpci, c_args: [ '-DNO_IOMMU_CHECK' ], link_args: static_arg)
endif

if get_option('build_noiommucheck_nofbreset').enabled()
    executable('kexec-lintel-noiommucheck-nofbreset', [ 'kexec-lintel.c' ], c_args: [ '-DNO_FBRESET', '-DNO_IOMMU_CHECK' ], link_args: static_arg)
endif
