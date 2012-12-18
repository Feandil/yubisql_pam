#ifndef __YUBISQL_PAM_AES__
#define __YUBISQL_PAM_AES__

#include <openssl/aes.h>
#include <stddef.h>
#include "otp-const.h"

AES_KEY *aes_init(const char* priv_key);
void aes_clean(AES_KEY *key);
struct otp* extract_otp(char* obfuscated_encrypted_otp, AES_KEY *key);
unsigned char* compute_hash(const char* digest_name, const char* input, size_t input_len);
char check_hash(const char* digest_name, const char* input, size_t input_len, const char* hash, size_t hash_len);

#endif /* __YUBISQL_PAM_AES__ */
