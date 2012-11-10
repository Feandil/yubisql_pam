#ifndef __YUBISQL_PAM_UTIL__
#define __YUBISQL_PAM_UTIL__

#include <stdint.h>
#include <string.h>
#include "otp-const.h"

uint16_t crc16 (const uint8_t * buf, size_t buf_size);

int modhex2hex(char* input, const size_t len);
unsigned char* hex2bin(const char* input, const size_t len);

struct otp {
  unsigned char private_id[OTP_PRIVID_BIN_LEN];
  unsigned int session_counter : 16;
  unsigned int timecode_low    : 16;
  unsigned int timecode_high   : 8;
  unsigned int token_count     : 8;
  unsigned int random          : 16;
  unsigned int crc             : 16;
}__attribute__ ((__packed__));

#endif /* __YUBISQL_PAM_UTIL__ */
