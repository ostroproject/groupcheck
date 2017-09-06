project('groupcheck', 'c')

systemd = dependency('libsystemd')

executable('groupcheck', 'groupcheck.c', 'main.c', dependencies : systemd, install : true)

executable('test-groups', 'groupcheck.c', 'test_groups.c', dependencies : systemd)
executable('test-directory', 'groupcheck.c', 'test_directory.c', dependencies : systemd)
