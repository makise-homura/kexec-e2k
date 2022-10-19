project('kexec-e2k', 'c', version: '1.0.1', meson_version: '>=0.53.0')
add_global_arguments('-DPROJ_VER="' + meson.project_version() + '"', language : 'c')

cc = meson.get_compiler('c')
cc.has_header_symbol('limits.h', 'PATH_MAX', required : true)

if not cc.has_function_attribute('packed')
    error('Your compiler does not support __attribute__((packed)), can not build here.')
endif

if not cc.has_function('strchrnul', prefix: '#include <string.h>', args: '-D_GNU_SOURCE')
    add_global_arguments('-DNO_STRCHRNUL', language : 'c')
endif

cmdline_length = get_option('cmdline_length')
if get_option('use_kernel_hdr')
    kdir = get_option('kernel_hdr_dir')
    if kdir == ''
        if meson.is_cross_build()
            warning('Cross build detected and kernel_hdr_dir is not set, falling back to cmdline_length value')
        else
            uname = run_command('uname', '-r', check: true).stdout().split('-')
            dirname = [ 'linux-headers' ]
            foreach i: uname
                if i == uname[uname.length() - 1]
                    dirname += 'common'
                else
                    dirname += i
                endif
            endforeach
            kdir = '/usr/src' / '-'.join(dirname) / 'include/'
            message('Guessing kernel headers path: ' + kdir)
        endif
    endif

    if not (kdir == '')
        cmdline_file = kdir / 'uapi/asm-generic/setup.h'
        fs = import('fs')
        if fs.is_file(cmdline_file)
            cmdline_length_res = cc.get_define('COMMAND_LINE_SIZE', prefix: '#include <' + cmdline_file + '>')
            if cmdline_length_res == ''
                error('Missing command line length in kernel headers. Check ' + cmdline_file  + 'for COMMAND_LINE_SIZE.')
            endif
            cmdline_length = cmdline_length_res.to_int()
            if cmdline_length == 0
                error('Incorrect command line length in kernel headers. Check ' + cmdline_file  + 'for COMMAND_LINE_SIZE.')
            endif
        else
            warning('Can not locate kernel headers, falling back to cmdline_length option')
        endif
    endif
endif
add_global_arguments('-DCOMMAND_LINE_SIZE=' + cmdline_length.to_string(), language : 'c')
message('Kernel command line length: ' + cmdline_length.to_string())

if not meson.is_cross_build()
    # Assume sizes are ok when cross compiling, because we are unable to check it
    sz_pfile = cc.sizeof('FILE*', prefix: '#include <stdio.h>')
    sz_plops = cc.sizeof('struct lintelops*', prefix: '#include "kexec-e2k.c"', args: [ '-DCOMMAND_LINE_SIZE=' + cmdline_length.to_string(), '-DAS_INCLUDE' ], include_directories: include_directories('.'))
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

version_src = vcs_tag(input: 'version.c.in', output: 'version.c', fallback: '(unknown)')

executable('kexec-e2k', 'kexec-e2k.c', version_src, install: true, link_args: static_arg)
