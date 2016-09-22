all-local: config.scm

lib_builddir = $(shell cd $(top_builddir)/guile-nacl && pwd)
docs_builddir = $(shell cd $(top_builddir)/doc && pwd)

moduledir=$(prefix)/share/guile/site/2.0/nacl

module_DATA =

config.scm: Makefile config.scm.in
	sed -e "s|@nacllibpath\@|$(lib_builddir)/libguile-nacl|" \
	    $(srcdir)/config.scm.in > config.scm

extlibdir = $(libdir)/guile/2.0/extensions

install-data-local: Makefile config.scm.in
	$(mkinstalldirs) $(DESTDIR)$(moduledir)
	sed -e "s|@nacllibpath\@|$(extlibdir)/libguile-nacl|" \
	    $(srcdir)/config.scm.in > $(DESTDIR)$(moduledir)/config.scm
	chmod 644 $(DESTDIR)$(moduledir)/config.scm

uninstall-local:
	rm -f $(DESTDIR)$(moduledir)/config.scm

CLEANFILES = config.scm

EXTRA_DIST = config.scm.in $(module_DATA)
