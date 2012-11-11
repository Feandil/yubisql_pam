#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql.h"

/* Define queries */
static const char yubisql_select_data[] = "SELECT publicid,privateid,key,digest FROM mapping WHERE username = ?;";
static const char yubisql_select_state[] = "SELECT session,timecode,tokencount FROM mapping WHERE username = ?;";
static const char yubisql_update_state[] = "UPDATE mapping SET session = ?, timecode = ?, tokencount = ? WHERE username = ?;";

static const char yubisql_create_credentials[] = "INSERT INTO mapping (username, publicid, privateid, key, digest) VALUES (?, ?, ?, ?, ?);";
static const char yubisql_delete_credentials[] = "DELETE FROM mapping WHERE username = ?;";
static const char yubisql_list_users[]   = "SELECT username FROM mapping;";

static const char yubisql_create_table[] = \
  "CREATE TABLE mapping(             \
      username TEXT PRIMARY KEY,     \
      publicid TEXT NOT NULL,        \
      key TEXT NOT NULL,             \
      privateid TEXT NOT NULL,       \
      session INTEGER DEFAULT 0,     \
      timecode INTEGER DEFAULT 0,    \
      tokencount INTEGER DEFAULT 0,  \
      digest TEXT NOT NULL           \
   );";

/* Transactions */
static const char yubisql_begin[] = "BEGIN IMMEDIATE;";
static const char yubisql_end[] = "COMMIT;";
static const char yubisql_rollback[] = "ROLLBACK;";

sqlite3*
init(const char* dbname)
{
  sqlite3 *ppDb = NULL;

  if (sqlite3_open(dbname, &ppDb) != SQLITE_OK) {
    sqlite3_close(ppDb);
    return NULL;
  }
  return ppDb;
}

void
sql_close(sqlite3* db)
{
  sqlite3_close(db);
}

int try_start_transaction(sqlite3* db)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request */
  response = sqlite3_prepare_v2(db, yubisql_begin, sizeof(yubisql_begin), &ppStmt, NULL);
  if (response != SQLITE_OK) {
    /* Should never ever happen */
    sqlite3_finalize(ppStmt);
    return OTP_SQL_ERR;
  }

  /* Run and verify response */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      return OTP_SQL_OK;
    case SQLITE_BUSY:
      return OTP_SQL_MAY_RETRY;
    default:
      return OTP_SQL_ERR;
  }
}

static int
try_or_rollback(sqlite3* db, sqlite3_stmt *ppStmt)
{
  int response;

  /* Run and verify response */
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

#define compile_or_rollback(db,ppStmt,response) \
  if (response != SQLITE_OK) {                  \
    /* Should never ever happen */              \
    sqlite3_finalize(ppStmt);                   \
    rollback(db);                               \
    return OTP_SQL_ERR;                         \
  }

int try_end_transaction(sqlite3* db)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request */
  response = sqlite3_prepare_v2(db, yubisql_end, sizeof(yubisql_end) - 1, &ppStmt, NULL);
  compile_or_rollback(db,ppStmt,response)

  return try_or_rollback(db, ppStmt);
}

static void
rollback_r(sqlite3* db, int rec)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the query */
  response = sqlite3_prepare_v2(db, yubisql_rollback, sizeof(yubisql_rollback) - 1, &ppStmt, NULL);
  if (response != SQLITE_OK) {
    /* Should never ever happen */
    sqlite3_finalize(ppStmt);
    return;
  }

  /* Run the query, and clean it immediately */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);

  /* If we didn't achieved to rollback, let's try another time */
  if ((response != SQLITE_OK)
      && (!rec)) {
    rollback_r(db, 1);
  }
}

void
rollback(sqlite3* db)
{
  rollback_r(db,0);
}

struct otp_data*
get_otp_data (sqlite3* db, const struct user* user)
{
  const unsigned char *ret;
  int response, len;
  sqlite3_stmt *ppStmt = NULL;
  struct otp_data *data;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_select_data, sizeof(yubisql_select_data), &ppStmt, NULL);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }
  response = sqlite3_bind_text(ppStmt, 1, user->name, (int)user->len, SQLITE_STATIC);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }

  /* Run it and verify the format of the response */
  response = sqlite3_step(ppStmt);
  if ((response != SQLITE_ROW)
      || (sqlite3_column_count(ppStmt) != 4)
      || (sqlite3_column_type(ppStmt, 0) != SQLITE_TEXT)
      || (sqlite3_column_type(ppStmt, 1) != SQLITE_TEXT)
      || (sqlite3_column_type(ppStmt, 2) != SQLITE_TEXT)
      || (sqlite3_column_type(ppStmt, 3) != SQLITE_TEXT)) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }

  /* Allocate the result struct */
  data = malloc(sizeof(struct otp_data));
  if (data == NULL) {
    sqlite3_finalize(ppStmt);
    return NULL;
  }

  /* Extract and copy each data */
  /* Public ID */
  ret = sqlite3_column_text(ppStmt,0);
  len = sqlite3_column_bytes(ppStmt,0);
  if (len == OTP_PUB_ID_HEX_LEN) {
    memcpy(data->pubid, ret, OTP_PUB_ID_HEX_LEN);
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }
  /* AES key */
  ret = sqlite3_column_text(ppStmt,2);
  len = sqlite3_column_bytes(ppStmt,2);
  if (len == OTP_KEY_HEX_LEN) {
    memcpy(data->key, ret, OTP_KEY_HEX_LEN);
  } else {
    sqlite3_finalize(ppStmt);
    free(data);
    return NULL;
  }
  /* Private ID hash */
  data->privid_hash = strdup((const char *)sqlite3_column_text(ppStmt,1));
  data->digest_name = strdup((const char *)sqlite3_column_text(ppStmt,3));

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

int
try_get_credentials(sqlite3* db, struct otp_state* store, const struct user* user)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_select_state, sizeof(yubisql_select_state), &ppStmt, NULL);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 1, user->name, (int)user->len, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)

  /* Run and verify response */
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

  return try_or_rollback(db, ppStmt);
}

int
try_update_credentials(sqlite3* db, const struct otp_state* otp, const struct user* user)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_update_state, sizeof(yubisql_update_state), &ppStmt, NULL);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_int(ppStmt, 1, otp->session_counter);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_int(ppStmt, 2, (int)otp->timecode);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_int(ppStmt, 3, otp->token_count);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 4, user->name, (int)user->len, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)

  /* Run and verify that it's ok */
  return try_or_rollback(db, ppStmt);
}

int
try_create_credentials(sqlite3* db, struct otp_data* data, const struct user* user)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_create_credentials, sizeof(yubisql_create_credentials), &ppStmt, NULL);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 1, user->name, (int)user->len, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 2, data->pubid, OTP_PUB_ID_HEX_LEN, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 3, data->privid_hash, -1, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 4, data->key, OTP_KEY_HEX_LEN, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 5, data->digest_name, -1, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)

  return try_or_rollback(db, ppStmt);
}

int
try_delete_credentials(sqlite3* db, const struct user* user)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  response = sqlite3_prepare_v2(db, yubisql_delete_credentials, sizeof(yubisql_delete_credentials), &ppStmt, NULL);
  compile_or_rollback(db,ppStmt,response)
  response = sqlite3_bind_text(ppStmt, 1, user->name, (int)user->len, SQLITE_STATIC);
  compile_or_rollback(db,ppStmt,response)

  return try_or_rollback(db, ppStmt);
}

void
list_users (sqlite3* db)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_list_users, sizeof(yubisql_list_users), &ppStmt, NULL);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    printf("Unable to search\n");
    return;
  }

  /* Extract all the responses */
  while ((response = sqlite3_step(ppStmt)) == SQLITE_ROW) {
    if ((sqlite3_column_count(ppStmt) != 1)
         || (sqlite3_column_type(ppStmt, 0) != SQLITE_TEXT)) {
       printf("Error while searching for users: database error\n");
    } else {
      printf("%s\n",sqlite3_column_text(ppStmt, 0));
    }
  }

  if (response == SQLITE_DONE) {
    return;
  }
  printf("Error while searching for users: SQL error\n");
}

void
create_database(sqlite3* db)
{
  int response;
  sqlite3_stmt *ppStmt = NULL;

  /* Prepare the request ! */
  response = sqlite3_prepare_v2(db, yubisql_create_table, sizeof(yubisql_create_table), &ppStmt, NULL);
  if (response != SQLITE_OK) {
    sqlite3_finalize(ppStmt);
    printf("Unable to prepare the query that would create the table\n");
    return;
  }

  /* Run and verify response */
  response = sqlite3_step(ppStmt);
  sqlite3_finalize(ppStmt);
  switch (response) {
    case SQLITE_DONE:
      printf("Database successfuly created\n");
      break;
    default:
      printf("Unable to create database (%i)\n", response);
      break;
  }
}

void
free_otp_data(struct otp_data *a)
{
  if (a->digest_name != NULL) {
    free(a->digest_name);
  }
  if (a->privid_hash != NULL) {
    free(a->privid_hash);
  }
  free(a);
}

