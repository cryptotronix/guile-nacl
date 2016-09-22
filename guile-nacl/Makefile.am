## The library

extlibdir = $(libdir)/guile/2.0/extensions

extlib_LTLIBRARIES = libguile-nacl.la

AM_CFLAGS = -I$(srcdir) $(WARN_CFLAGS) $(DEBUG_CFLAGS)

libguile_nacl_la_SOURCES = guile-nacl.c
libguile_nacl_la_CFLAGS = $(AM_CFLAGS) $(GUILE_CFLAGS)
libguile_nacl_la_LIBADD = -lsodium $(GUILE_LIBS)
libguile_nacl_la_LDFLAGS = -export-dynamic -module -avoid-version

noinst_HEADERS = guile-nacl.h


SUFFIXES = .x

GUILE_SNARF_CFLAGS = $(libguile_nacl_la_CFLAGS)

.c.x:
	guile-snarf $(GUILE_SNARF_CFLAGS) $< > $@ \
	|| { rm $@; false; }

C_FILES = $(libguile_nacl_la_SOURCES)
DOT_X_FILES = $(C_FILES:.c=.x)

BUILT_SOURCES = $(DOT_X_FILES)

CLEANFILES = $(DOT_X_FILES)
