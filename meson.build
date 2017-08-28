project('groupcheck', 'c')

systemd = dependency('libsystemd')

executable('groupcheck', 'groupcheck.c', 'main.c', dependencies : systemd, install : true)

executable('test-groupcheck', 'groupcheck.c', 'test_groups.c', dependencies : systemd)
