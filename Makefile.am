SUBDIRS = guile-nacl nacl tests doc

env: Makefile env.in
	sed -e "s|@top_srcdir\@|$(shell cd $(top_srcdir) && pwd)|" \
	    $(srcdir)/env.in > env
	chmod +x env

BUILT_SOURCES = env
CLEANFILES = env

scmdir=$(prefix)/share/guile/site/2.0

scm_DATA = nacl.scm

EXTRA_DIST = env.in autogen.sh HACKING $(scm_DATA)
