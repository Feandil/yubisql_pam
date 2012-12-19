#ifndef __YUBISQL_PAM_OTP_CONST__
#define __YUBISQL_PAM_OTP_CONST__

#define OTP_PUB_ID_HEX_LEN 12ul

#define OTP_PRIVID_BIN_LEN 6ul
#define OTP_PRIVID_HEX_LEN 12ul

#define OTP_KEY_BIN_LEN 128ul
#define OTP_KEY_HEX_LEN 32ul

#define OTP_BIN_LEN 16ul
#define OTP_MESSAGE_HEX (OTP_KEY_HEX_LEN + OTP_PUB_ID_HEX_LEN)

#define OTP_CRC 0xf0b8

struct otp {
  unsigned char private_id[OTP_PRIVID_BIN_LEN];
  unsigned int session_counter : 16;
  unsigned int timecode_low    : 16;
  unsigned int timecode_high   : 8;
  unsigned int token_count     : 8;
  unsigned int random          : 16;
  unsigned int crc             : 16;
}__attribute__ ((__packed__));

#endif /* __YUBISQL_PAM_OTP_CONST__ */
