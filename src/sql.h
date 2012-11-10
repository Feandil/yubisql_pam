#ifndef __YUBISQL_PAM_SQL__
#define __YUBISQL_PAM_SQL__

#include <sqlite3.h>
#include "otp-const.h"

struct user {
  const char *name;
  size_t len;
};

struct otp_state {
  unsigned short session_counter;
  unsigned int timecode;
  unsigned char  token_count;
};

struct otp_data {
  char pubid[OTP_PUB_ID_HEX_LEN];
  char privid[OTP_PRIVID_HEX_LEN];
  char key[OTP_KEY_HEX_LEN] ;
};

#define OTP_SQL_OK         0
#define OTP_SQL_ERR        1
#define OTP_SQL_MAY_RETRY  2

sqlite3* init(const char* dbname);
void sql_close(sqlite3* db);

struct otp_data* get_otp_data (sqlite3* db, const struct user* user);

/* ! Start transaction ! */
int try_get_credentials(sqlite3* db, struct otp_state* store, const struct user* user);

/* Abort transaction */
void rollback(sqlite3* db);

/* End transaction */
int try_update_credentials(sqlite3* db, const struct otp_state* otp, const struct user* user);

#endif /* __YUBISQL_PAM_SQL__ */
