project('SodiumCipherStream', 'cpp',
        default_options: ['cpp_std=c++20'])

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
if get_option('static')
  libscs_static = static_library('SodiumCipherStream',
				 sources: 'SodiumCipherStream.cpp',
				 dependencies: libsodium_dep)
else
  libscs = shared_library('SodiumCipherStream',
			  sources: 'SodiumCipherStream.cpp',
			  dependencies: libsodium_dep)
endif

# Tests
gtest = meson.get_compiler('cpp').find_library('gtest', required: false)
if gtest.found()
  test_all = executable('test_all',
			sources: ['test/main.cpp',
				  'test/SodiumCipherStream-test.cpp',
				  'test/AsyncCipherStream-test.cpp',
				  'SodiumCipherStream.cpp',
				  'AsyncCipherStream.cpp'],
			dependencies: [gtest, libsodium_dep])

  test('all', test_all)
endif
