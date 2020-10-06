project('SodiumCipherStream', 'cpp',
        default_options: ['cpp_std=c++17'])

# Build types
if get_option('buildtype').startswith('debug')
  add_project_arguments('-Wall', '-Wextra', '-Werror', '-DFORTIFY_SOURCE=1',
                        '-ggdb3',
                        '-fsanitize=address',
                        # '-fsanitize=leak',
                        '-fsanitize=undefined',
			'-Og',
                        language : 'cpp')
  add_project_link_arguments(
    '-lasan',
    # '-ltsan',
    '-lubsan',
    language : 'cpp')
elif get_option('buildtype') == 'release'
  add_project_arguments('-DNDEBUG', '-O3', '-s',
                        language : 'cpp')
endif

# Dependencies
libsodium_dep = dependency('libsodium')

# Binaries
static_library('SodiumCipherStream',
	       sources: 'SodiumCipherStream.cpp',
	       dependencies: libsodium_dep)
