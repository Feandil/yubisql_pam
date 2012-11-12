#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "aes.h"
#include "util.h"

AES_KEY *aes_init(const char* priv_key)
{
  /* Exctract binary value */
  unsigned char *bin_priv_key = hex2bin(priv_key, OTP_KEY_HEX_LEN);

  /* Init key */
  AES_KEY *key = calloc(sizeof(AES_KEY), 1);
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
  unsigned char *otp = calloc(sizeof(char), OTP_KEY_BIN_LEN);
  if (otp == NULL) {
    return NULL;
  }

  /* Use openssl to decrypt */
  AES_decrypt(bin_encrypted_otp, otp, key);

  /* Clean cache */
  free(bin_encrypted_otp);

  return (struct otp*) otp;
}

unsigned char*
compute_hash(const char* digest_name, const char* input, size_t input_len)
{
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char *md_value;
  unsigned int md_len;

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname(digest_name);

  if (md == NULL) {
    printf("Unsuporter digest '%s'\n", digest_name);
    return NULL;
  }
  md_value = calloc(sizeof(char), EVP_MAX_MD_SIZE);
  if (md_value == NULL) {
    printf("Malloc error\n");
    return NULL;
  }

  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, input, input_len);
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  return md_value;
}

char
check_hash(const char* digest_name, const char* input, size_t input_len, const char* hash, size_t hash_len)
{
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname(digest_name);

  if (md == NULL) {
    return 1;
  }

  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, input, input_len);
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  if (md_len != hash_len) {
    return 2;
  }

  if (memcmp(hash, md_value, hash_len)) {
    return 3;
  }
  return 0;
}
