#ifndef __YUBISQL_PAM_UTIL__
#define __YUBISQL_PAM_UTIL__

#include <stdint.h>
#include <string.h>
#include "otp-const.h"

uint16_t crc16 (const uint8_t * buf, size_t buf_size);

int modhex2hex(char* input, const size_t len);
unsigned char* hex2bin(const char* input, const size_t len);

#endif /* __YUBISQL_PAM_UTIL__ */
