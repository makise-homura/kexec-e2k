project('kexec-lintel', 'c', meson_version: '>=0.50.0')
meson.get_compiler('c').has_header_symbol('limits.h', 'PATH_MAX', required : true)

if get_option('build_generic').enabled() or get_option('build_noiommucheck').enabled()
    libpci = dependency('libpci', required : false)
    if not libpci.found()
        add_global_arguments('-DNO_BRIDGE_RESET', language : 'c')
    endif
endif

if get_option('build_generic').enabled()
    executable('kexec-lintel', [ 'kexec-lintel.c', 'fbreset.c', 'iommucheck.c' ], dependencies: libpci)
endif

if get_option('build_nofbreset').enabled()
    executable('kexec-lintel-nofbreset', [ 'kexec-lintel.c', 'iommucheck.c' ], c_args: [ '-DNO_FBRESET' ])
endif

if get_option('build_noiommucheck').enabled()
    executable('kexec-lintel-noiommucheck', [ 'kexec-lintel.c', 'fbreset.c' ], dependencies: libpci, c_args: [ '-DNO_IOMMU_CHECK' ])
endif

if get_option('build_noiommucheck_nofbreset').enabled()
    executable('kexec-lintel-noiommucheck-nofbreset', [ 'kexec-lintel.c' ], c_args: [ '-DNO_FBRESET', '-DNO_IOMMU_CHECK' ])
endif
