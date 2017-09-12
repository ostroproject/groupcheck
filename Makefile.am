sbin_PROGRAMS = groupcheck
groupcheck_SOURCES = groupcheck.c main.c
groupcheck_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
groupcheck_LDADD = $(LIBSYSTEMD_LIBS)

noinst_PROGRAMS = test-process test-directory test-bus
test_process_SOURCES = groupcheck.c test_process.c
test_process_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
test_process_LDADD = $(LIBSYSTEMD_LIBS)

test_bus_SOURCES = groupcheck.c test_bus.c
test_bus_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
test_bus_LDADD = $(LIBSYSTEMD_LIBS)

test_directory_SOURCES = groupcheck.c test_directory.c
test_directory_CPPFLAGS = $(LIBSYSTEMD_CPPFLAGS)
test_directory_LDADD = $(LIBSYSTEMD_LIBS)
