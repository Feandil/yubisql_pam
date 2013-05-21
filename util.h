#ifndef __YUBISQL_PAM_UTIL__
#define __YUBISQL_PAM_UTIL__

#include <stdint.h>
#include <string.h>
#include "otp-const.h"

struct user {
  const char *name;
  int len;
};

int verify_user(const char* username, const size_t username_len, struct user* user);

uint16_t crc16 (const uint8_t * buf, size_t buf_size);

int check_modhex(char* input, const size_t len);
int modhex2hex(char* input, const size_t len);
int check_hex(const char *input, const int len);
unsigned char* hex2bin(const char* input, const size_t len);
char* bin2hex(const char* input, const size_t len);
int forget_real_credentials(void);

#endif /* __YUBISQL_PAM_UTIL__ */
