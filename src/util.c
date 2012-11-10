#include <string.h>
#include <stdlib.h>

#include "util.h"

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

/* No checks here, need to have some real hex in input */
unsigned char*
hex2bin(const char* input, const size_t len)
{
  unsigned char tmp;
  unsigned char *res, *out;
  size_t pos;

  res = malloc(len/2);
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

