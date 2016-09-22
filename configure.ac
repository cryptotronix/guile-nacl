AC_PREREQ(2.65)
AC_INIT(guile-nacl, 0.0.1, [bugs@cryptotronix.com])
AC_CONFIG_SRCDIR(nacl.scm)
AC_CONFIG_AUX_DIR(build-aux)

LT_INIT

AC_CONFIG_HEADER(config.h)

AM_INIT_AUTOMAKE([color-tests silent-rules])

AC_DISABLE_STATIC

AC_PROG_CC

WARN_CFLAGS=-Wall
AC_ARG_ENABLE([Werror], AC_HELP_STRING([--disable-Werror],[Don't stop the build on errors]),
        [], WARN_CFLAGS="-Wall -Werror")
AC_SUBST(WARN_CFLAGS)

PKG_CHECK_MODULES(GUILE, [guile-2.0 >= 2.0.0])

AC_CHECK_LIB([libsodium], [nacl_init])

AC_CONFIG_FILES(
Makefile
guile-nacl/Makefile
nacl/Makefile
tests/Makefile
doc/Makefile
)

AC_OUTPUT
