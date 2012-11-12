#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "util.h"

int
verify_user(const char* username, const size_t username_len, struct user* user)
{
  size_t temp_len;

  /* Let's verify the username */
  for (temp_len = 0; temp_len < username_len; ++temp_len) {
    if ((*(username + temp_len) < 0x61) || (*(username + temp_len) > 0x7A)) {
      return -1;
    }
  }

  /* Verify for overflow */
  if (username_len > INT_MAX) {
    return -1;
  }
  user->name = username;
  user->len = (int) username_len;

  return 0;
}

int
check_modhex(char* input, const size_t len)
{
  size_t temp;
  for (temp = 0; temp < len; ++temp) {
    if (*input > 0x61) {
      if (*input < 0x6C) {
        continue;
      } else if (*input > 0x73) {
        if (*input > 0x77) {
          return -1;
        }
        continue;
      } else {
        switch (*input) {
          case 'l':
            continue;
          case 'n':
            continue;
          case 'r':
            continue;
          default:
            return -1;
         }
      }
    } else {
      return -1;
    }
    ++input;
  }
  return 0;
}

int
modhex2hex(char* input, const size_t len)
{
  size_t temp;
  for (temp = 0; temp < len; ++temp) {
    if (*input > 0x61) {
      if (*input < 0x6C) {
        /* *input > 0x61 thus it *input - 0x32 > 0 */
        *input = (char) (*input - 0x32);
        if (*input < 0x32) {
          *input ^= 0x01;
        }
      } else if (*input > 0x73) {
        if (*input > 0x77) {
          return -1;
        }
        /* *input > 0x77 thus it *input - 0x10 > 0 */
        *input = (char) (*input - 0x10);
      } else {
        switch (*input) {
          case 'l':
            *input = 'a';
            break;
          case 'n':
            *input = 'b';
            break;
          case 'r':
            *input = 'c';
            break;
          default:
            return -1;
         }
      }
    } else {
      return -1;
    }
    ++input;
  }
  return 0;
}

int
check_hex(const char *input, const int len)
{
  const char *end;
  for (end = input + len; input < end; ++input) {
    if (*input <= 0x3A) {
      if (*input < 0x30) {
        return -1;
      } else {
        continue;
      }
    }
    if (*input <= 0x66) {
      if (*input < 0x61) {
        return -1;
      } else {
        continue;
      }
    }
    return -1;
  }
  return 0;
}

/* No checks here, need to have some real hex in input */
unsigned char*
hex2bin(const char* input, const size_t len)
{
  unsigned char tmp;
  unsigned char *res, *out;
  size_t pos;

  res = calloc(sizeof(char), len/2);
  if (res == NULL) {
    return res;
  }
  out = res;

  for (pos = 0; pos < len; ++pos) {
    /* 'Hex' characters are:
     *  0-9: 0x30-0x3A
     *  a-z: 0x61-0x66
     */
    if (*input < 0x3A) {
      tmp = (unsigned char) (*input - 0x30);
    } else {
      tmp = (unsigned char) (*input - 0x57);
    }
    if (pos % 2) {
      *out |= tmp;
      ++out;
    } else {
      /* We cannot overflow here as tmp is supposed to be <= 0xf */
      *out = (unsigned char) (tmp << 4);
    }
    ++input;
  }
  return res;
}

static const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char*
bin2hex(const char* input, const size_t len)
{
  char *res, *out;
  size_t pos;

  res = calloc((len * 2) + 1, 1);
  if (res == NULL) {
    return res;
  }
  out = res;

  for (pos = 0; pos < len; ++pos) {
    *out = hex_table[(int)(((unsigned char)(*input)) >> 4)];
    ++out;
    *out = hex_table[(int)((*input) & 0x0f)];
    ++out;
    ++input;
  }
  return res;
}

uint16_t
crc16 (const uint8_t * data, size_t size)
{
  uint16_t crc = 0xffff;
  uint8_t i;

  while (size--) {
    crc = (uint16_t) (crc ^ *data++);
    for (i = 0; i < 8; i++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0x8408;
      } else {
        crc = (crc >> 1);
      }
    }
  }

  return crc;
}

