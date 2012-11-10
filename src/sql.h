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
  char key[OTP_KEY_HEX_LEN] ;
  char *digest_name;
  char *privid_hash;
};

void free_otp_data(struct otp_data *a);

#define OTP_SQL_OK         0
#define OTP_SQL_MALLOC_ERR 1
#define OTP_SQL_ERR        2
#define OTP_SQL_MAY_RETRY  3

sqlite3* init(const char* dbname);
void sql_close(sqlite3* db);

struct otp_data* get_otp_data (sqlite3* db, const struct user* user);

int try_start_transaction(sqlite3* db);
void rollback(sqlite3* db);
int try_end_transaction(sqlite3* db);

/* Those functions SHOULD be used only inside transactions */
int try_get_credentials(sqlite3* db, struct otp_state* store, const struct user* user);
int try_update_credentials(sqlite3* db, const struct otp_state* otp, const struct user* user);

#endif /* __YUBISQL_PAM_SQL__ */
