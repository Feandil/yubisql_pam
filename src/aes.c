#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "util.h"

AES_KEY *aes_init(const char* priv_key)
{
  /* Exctract binary value */
  unsigned char *bin_priv_key = hex2bin(priv_key, OTP_KEY_HEX_LEN);

  /* Init key */
  AES_KEY *key = (AES_KEY*) malloc(sizeof(AES_KEY));
  if (key == NULL) {
    return NULL;
  }
  AES_set_decrypt_key(bin_priv_key, OTP_KEY_BIN_LEN, key);

  /* Clean cache */
  free(bin_priv_key);

  return key;
}

void aes_clean(AES_KEY *key)
{
  free(key);
}

struct otp* extract_otp(char* obfuscated_encrypted_otp, AES_KEY *key)
{
  /* De-obfuscate OTP */
  modhex2hex(obfuscated_encrypted_otp, OTP_KEY_HEX_LEN);

  /* Exctract binary values */
  unsigned char *bin_encrypted_otp = hex2bin(obfuscated_encrypted_otp, OTP_KEY_HEX_LEN);;

  /* Allocate output buffer */
  unsigned char *otp = malloc(OTP_KEY_BIN_LEN);
  if (otp == NULL) {
    return NULL;
  }

  /* Use openssl to decrypt */
  AES_decrypt(bin_encrypted_otp, otp, key);

  /* Clean cache */
  free(bin_encrypted_otp);

  return (struct otp*) otp;
}
