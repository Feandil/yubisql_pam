#ifndef __YUBISQL_PAM_DEBUG__
#define __YUBISQL_PAM_DEBUG__

#include <syslog.h>
#include <stdio.h>

#define SYSTEM_PRINTF(debug, ...)                            \
  if (debug) {                                               \
    syslog(LOG_AUTH|LOG_DEBUG, "pam_yubisql: " __VA_ARGS__); \
  }

#define STDOUT_PRINTF(debug, ...) \
  if (debug) {                    \
     printf(__VA_ARGS__);         \
  }

#define PRINTF(debug, syslog, ...)    \
  if (syslog) {                       \
    SYSTEM_PRINTF(debug, __VA_ARGS__) \
  } else {                            \
    STDOUT_PRINTF(debug, __VA_ARGS__) \
  }

#endif /*__YUBISQL_PAM_DEBUG__ */
