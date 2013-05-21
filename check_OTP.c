#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "otp.h"
#include "util.h"

static void
usage(int err)
{
  if (err > 0) {
    switch(err) {
      case 1:
        printf("Too many arguments\n");
        break;
      case 2:
        printf("Database not set\n");
        break;
      case 3:
        printf("User not set\n");
        break;
      case 4:
        printf("OTP not set\n");
        break;
      default:
        printf("Unknown usage error (%i), please contact us\n", err);
        exit(-2);
        break;
    }
  } else {
    printf("check_OTP: Check the output of a yubikey against a local database\n");
    printf("   (Package: %s. Bug report to %s)\n\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    printf("Usage: ./check_OTP [-hvl] -s <database> -u <user> -o <OTP>\n");
    printf("        Exit code specifies the result: 0 = OK, !0 = ERROR\n");
    printf("Options:\n");
    printf(" -h, --help                 Print this ...\n");
    printf(" -v                         Print errors occurring when parsing the input\n");
    printf(" -l                         Use syslog to log errors (Only useful when -v is set)\n");
    exit(err);
  }
  exit(-1);
}


int
main(int argc, char *argv[])
{
  char verbose = 0;
  char syslog = 0;
  char *sql_db = NULL;
  char *username = NULL;
  char *otp = NULL;
  int opt;

  while((opt = getopt(argc, argv, "hvls:u:o:")) != -1) {
    switch(opt) {
      case 'h':
        usage(0);
        break;
      case 'v':
        ++verbose;
        break;
      case 'l':
        ++syslog;
        break;
      case 's':
        sql_db = optarg;
        break;
      case 'u':
        username = optarg;
        break;
      case 'o':
        otp = optarg;
        break;
     }
  }

  if(argc > optind) {
    usage(1);
  }
  if (sql_db == NULL) {
    usage(2);
  }
  if (username == NULL) {
    usage(3);
  }
  if (otp == NULL) {
    usage(4);
  }

  if (forget_real_credentials() != 0) {
    if (verbose) {
      printf("Unable to fix uid/gid\n");
    }
    return -EPERM;
  }

  return check_otp(sql_db, username, strlen(username), otp, verbose, syslog);
}
