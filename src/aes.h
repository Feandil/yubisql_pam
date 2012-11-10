#ifndef __YUBISQL_PAM_AES__
#define __YUBISQL_PAM_AES__

#include <openssl/aes.h>
#include "util.h"

AES_KEY *aes_init(const char* priv_key);
void aes_clean(AES_KEY *key);
struct otp* extract_otp(char* obfuscated_encrypted_otp, AES_KEY *key);

#endif /* __YUBISQL_PAM_AES__ */
