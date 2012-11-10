#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql.h"

#define SELECT_DATA "SELECT publicid,privateid,key FROM mapping WHERE username = \"%.*s\";"
#define SELECT_DATA_MIN_LEN 70

#define SQL_REQUEST_LEN 200
#define SELECT_STATE "SELECT session,timecode,tokencount FROM mapping WHERE username = \"%.*s\";"
#define UPDATE_STATE "UPDATE mapping SET session = %hu, timecode = %u, tokencount = %hhu WHERE username = \"%.*s\";"
#define BEGIN_TRANSLATION "BEGIN IMMEDIATE;"
#define END_TRANSLATION "COMMIT;"

#define ROLLBACK "ROLLBACK;"
#define ROLLBACK_LEN 10

sqlite3* init(const char* dbname)
{
  sqlite3 *ppDb = NULL;

  if (sqlite3_open(dbname, &ppDb) != SQLITE_OK) {
    sqlite3_close(ppDb);
    return NULL;
  }
  return ppDb;
}

void sql_close(sqlite3* db)
{
  sqlite3_close(db);
}

static void rollback_r(sqlite3* db, int rec)
{
  size_t len;
  char *request;
  int response;
  sqlite3_stmt *ppStmt = NULL;

  len = ROLLBACK_LEN;
  request = malloc(len);
  snprintf(request, len, ROLLBACK);

  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  free(request);

  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  if ((response != SQLITE_OK)
      && (!rec)) {
    rollback_r(db,1);
  }
}

void rollback(sqlite3* db)
{
  rollback_r(db,0);
}

struct otp_data* get_otp_data (sqlite3* db, const struct user* user)
{
  size_t len;
  char *request;
  const unsigned char *ret;
  int response;
  sqlite3_stmt *ppStmt = NULL;
  struct otp_data *data;

  /* format the request */
  len = SELECT_DATA_MIN_LEN + user->len;
  request = malloc(len);
  len = snprintf(request, len, SELECT_DATA, user->len, user->name);

  /* invoque ! */
  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  free(request);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }
  response = sqlite3_step(ppStmt);
  if ((response != SQLITE_ROW)
      || (sqlite3_column_count(ppStmt) != 3)
      || (sqlite3_column_type(ppStmt,0) != SQLITE_TEXT)
      || (sqlite3_column_type(ppStmt,1) != SQLITE_TEXT)
      || (sqlite3_column_type(ppStmt,2) != SQLITE_TEXT)) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }

  /* Allocate the result struct */
  data = malloc(sizeof(struct otp_data));
  if (data == NULL) {
    return NULL;
  }

  /* Extract and copy each data */
  ret = sqlite3_column_text(ppStmt,0);
  len = sqlite3_column_bytes(ppStmt,0);
  if (len == OTP_PUB_ID_HEX_LEN) {
    memcpy(data->pubid, ret, len);
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }
  ret = sqlite3_column_text(ppStmt,1);
  len = sqlite3_column_bytes(ppStmt,1);
  if (len == OTP_PRIVID_HEX_LEN) {
    memcpy(data->privid, ret, len);
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }
  ret = sqlite3_column_text(ppStmt,2);
  len = sqlite3_column_bytes(ppStmt,2);
  if (len == OTP_KEY_HEX_LEN) {
    memcpy(data->key, ret, len);
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }

  /* If there is more data, we failed */
  if (sqlite3_step(ppStmt) == SQLITE_DONE) {
    sqlite3_finalize(ppStmt);
    return data;
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }
}

int try_get_credentials(sqlite3* db, struct otp_state* store, const struct user* user)
{
  size_t len;
  char *request;
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Begin transalation */

  /* format the request */
  len = SQL_REQUEST_LEN;
  request = malloc(len);
  len = snprintf(request, len, BEGIN_TRANSLATION);

  /* invoque ! */
  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    free(request);
    if (response == SQLITE_BUSY) {
      return OTP_SQL_MAY_RETRY;
    }
    return OTP_SQL_ERR;
  }
  /* Verify response */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      break;
    case SQLITE_BUSY:
      free(request);
      return OTP_SQL_MAY_RETRY;
    default:
      free(request);
      return OTP_SQL_ERR;
  }

  /* Obtain state */

  /* format the request */
  len = snprintf(request, SQL_REQUEST_LEN, SELECT_STATE, user->len, user->name);
  ppStmt = NULL;

  /* invoque ! */
  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  free(request);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    if (response == SQLITE_BUSY) {
      return OTP_SQL_MAY_RETRY;
    }
    return OTP_SQL_ERR;
  }

  /* Verify response */
  response = sqlite3_step(ppStmt);
  switch (response) {
    case SQLITE_ROW:
      break;
    case SQLITE_BUSY:
      sqlite3_finalize(ppStmt);
      rollback(db);
      return OTP_SQL_MAY_RETRY;
    default:
      sqlite3_finalize(ppStmt);
      rollback(db);
      return OTP_SQL_ERR;
  }

  if ((sqlite3_column_count(ppStmt) != 3)
      || (sqlite3_column_type(ppStmt,0) != SQLITE_INTEGER)
      || (sqlite3_column_type(ppStmt,1) != SQLITE_INTEGER)
      || (sqlite3_column_type(ppStmt,2) != SQLITE_INTEGER)) {
    sqlite3_finalize(ppStmt);
    return OTP_SQL_ERR;
  }

  store->session_counter = (unsigned short) sqlite3_column_int(ppStmt, 0);
  store->timecode = (unsigned int) sqlite3_column_int(ppStmt, 1);
  store->token_count = (unsigned char) sqlite3_column_int(ppStmt, 2);

  /* Verify that it's the only response */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      return OTP_SQL_OK;
    case SQLITE_BUSY:
      rollback(db);
      return OTP_SQL_MAY_RETRY;
    default:
      rollback(db);
      return OTP_SQL_ERR;
  }
}

int try_update_credentials(sqlite3* db, const struct otp_state* otp, const struct user* user)
{
  size_t len;
  char *request;
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Update the state */

  /* format the request */
  len = SQL_REQUEST_LEN;
  request = malloc(len);
  len = snprintf(request, len, UPDATE_STATE, otp->session_counter, otp->timecode, otp->token_count, user->len, user->name);

  /* invoque ! */
  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    free(request);
    rollback(db);
    if (response == SQLITE_BUSY) {
      return OTP_SQL_MAY_RETRY;
    }
    return OTP_SQL_ERR;
  }

  /* Verify that it's ok */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      break;
    case SQLITE_BUSY:
      free(request);
      rollback(db);
      return OTP_SQL_MAY_RETRY;
    default:
      free(request);
      rollback(db);
      return OTP_SQL_ERR;
  }

  /* Close the translation */

  /* format the request */
  len = snprintf(request, SQL_REQUEST_LEN, END_TRANSLATION);
  ppStmt = NULL;

  /* invoque ! */
  response = sqlite3_prepare(db, request, len, &ppStmt, NULL);
  free(request);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    rollback(db);
    if (response == SQLITE_BUSY) {
      return OTP_SQL_MAY_RETRY;
    }
    return OTP_SQL_ERR;
  }

  /* Verify that it's ok*/
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      return OTP_SQL_OK;
    case SQLITE_BUSY:
      rollback(db);
      return OTP_SQL_MAY_RETRY;
    default:
      rollback(db);
      return OTP_SQL_ERR;
  }
}
