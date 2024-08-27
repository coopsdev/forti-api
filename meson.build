project('forti_api', 'cpp',
        version : '0.1.4',
        default_options : ['warning_level=3', 'cpp_std=c++26'])

json_dep = dependency('nlohmann_json', required: true)
libcurl_dep = dependency('libcurl', required: true)

if get_option('buildtype') == 'debug'
    executable('forti_api', 'main.cpp',
               dependencies: [json_dep, libcurl_dep],
               include_directories: 'include',
               install: false
    )
endif
