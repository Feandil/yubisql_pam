ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign
AM_CFLAGS = -Wall -Wextra -Werror \
        -Wbad-function-cast \
        -Wcast-align \
        -Wcast-qual \
        -Wconversion \
        -Wformat-nonliteral \
        -Wformat-security \
        -Winit-self \
        -Wlogical-op \
        -Wmissing-declarations \
        -Wmissing-include-dirs \
        -Wmissing-format-attribute \
        -Wmissing-prototypes \
        -Wnested-externs \
        -Wpointer-arith \
        -Wredundant-decls \
        -Wshadow \
        -Wstrict-prototypes \
        -Wwrite-strings \
        -Wundef \
        -Wunused \
        -Wno-unused-parameter \
        -Wno-format-zero-length \
        -Wno-format-y2k \
        -Wunsafe-loop-optimizations

AM_LDFLAGS = -no-install -Wl

libdir = $(PAMDIR)

noinst_LTLIBRARIES = libyubisql.la
libyubisql_la_SOURCES = aes.c otp.c sql.c util.c
libyubisql_la_CFLAGS = @OPENSSL_CFLAGS@ @SQLITE_CFLAGS@ $(AM_CFLAGS)
libyubisql_la_LIBADD = @OPENSSL_LIBS@ @SQLITE_LIBS@

bin_PROGRAMS = check_OTP
sbin_PROGRAMS = manage_OTP

check_OTP_SOURCES = check_OTP.c
check_OTP_LDADD = libyubisql.la

manage_OTP_SOURCES = manage_OTP.c
manage_OTP_LDADD = libyubisql.la

lib_LTLIBRARIES = pam_yubisql.la
pam_yubisql_la_SOURCES = pam_yubisql.c
pam_yubisql_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version
pam_yubisql_la_LIBADD = libyubisql.la -lpam
