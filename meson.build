project('groupcheck', 'c')

systemd = dependency('libsystemd')

executable('groupcheck', 'groupcheck.c', 'main.c', dependencies : systemd, install : true, install_dir : get_option('sbindir'))

executable('test-process', 'groupcheck.c', 'test_process.c', dependencies : systemd)
executable('test-bus', 'groupcheck.c', 'test_bus.c', dependencies : systemd)
executable('test-directory', 'groupcheck.c', 'test_directory.c', dependencies : systemd)
