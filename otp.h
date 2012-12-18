#ifndef __YUBISQL_PAM_OTP__
#define __YUBISQL_PAM_OTP__

#include "aes.h"
#include "sql.h"
#include "otp-const.h"

#define OTP_OK  0
#define OTP_ERR 1

int check_otp(const char* sql_db, const char *username, const size_t username_len, char* otp, char debug, char authlog);

#endif /* __YUBISQL_PAM_OTP__ */
