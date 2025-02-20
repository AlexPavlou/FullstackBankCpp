project('bank', 'cpp', default_options: ['cpp_std=c++17'])

cpp_compiler = meson.get_compiler('cpp')

# Dependencies
pg = dependency('libpq', required: true)
hiredis_dep = dependency('hiredis', required: true)

# Directories
inc_dirs = include_directories('include')

# Source files
src_files = files('src/bank.cpp')

# Executable
executable('bank', src_files,
    dependencies: [pg, hiredis_dep],
    include_directories: inc_dirs
)
