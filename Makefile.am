sbin_PROGRAMS = groupcheck
groupcheck_SOURCES = groupcheck.c main.c
groupcheck_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
groupcheck_LDADD = $(LIBSYSTEMD_LIBS)

noinst_PROGRAMS = test_groups test_directory
test_groups_SOURCES = groupcheck.c test_groups.c
test_groups_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
test_groups_LDADD = $(LIBSYSTEMD_LIBS)

test_directory_SOURCES = groupcheck.c test_directory.c
test_directory_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
test_directory_LDADD = $(LIBSYSTEMD_LIBS)
