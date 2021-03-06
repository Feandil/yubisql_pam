#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([pam_yubisql], [1.0], [git@lerya.net])
AC_CONFIG_SRCDIR([check_OTP.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT

# Checks for header files.
AC_CHECK_HEADERS([limits.h stddef.h stdint.h stdlib.h string.h syslog.h unistd.h])
AC_CHECK_HEADERS([security/pam_appl.h] [security/pam_modules.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([openssl/aes.h openssl/evp.h], [],
  [AC_MSG_ERROR([[Openssl aes header files not found, install openssl-dev.]])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memchr memset strdup strerror setreuid setregid])

case "$build_os" in
freebsd*)
  AC_SUBST(PAMDIR, "/usr/local/lib")

  AC_SUBST(OPENSSL_CFLAGS, "")
  AC_SUBST(OPENSSL_LIBS, "-lssl -lcrypto")

  if ( test -z ${PKG_CONFIG}); then
    PKG_CONFIG=/usr/local/bin/pkg-config
  fi
  ;;
*)
  AC_SUBST(PAMDIR, "/lib/security")

  PKG_CHECK_MODULES([OPENSSL], [openssl])
  AC_SUBST([OPENSSL_CFLAGS])
  AC_SUBST([OPENSSL_LIBS])
  ;;
esac

AC_MSG_NOTICE([PAM installation path $PAMDIR])

PKG_CHECK_MODULES(SQLITE, sqlite3)
AC_SUBST([SQLITE_CFLAGS])
AC_SUBST([SQLITE_LIBS])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:
  Version:            ${VERSION}
  Host type:          ${host}
  Compiler:           ${CC}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
])

