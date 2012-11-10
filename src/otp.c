#include "otp.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_RETRIES 3

#ifndef DBG
#define DBG(x) printf("%s\n", x);
#endif

int
check_otp(const char* sql_db, const char *username, const size_t username_len, char* otp, char debug)
{
  int temp;
  int ret;
  unsigned char *priv_id;
  size_t temp_len;
  struct user user;
  sqlite3 *db;
  AES_KEY *key;
  struct otp* otp_dec;
  struct otp_data* data;
  struct otp_state store;

  /* Let's verify the username */
  for (temp_len = 0; temp_len < username_len; ++temp_len) {
    if ((*(username + temp_len) < 0x61) || (*(username + temp_len) > 0x7A)) {
      DBG("Unauthorized char in the username")
      return OTP_ERR;
    }
  }

  user.name = username;
  user.len = username_len;

  db = init(sql_db);
  if (db == NULL) {
    DBG("Error in the database initiation")
    return OTP_ERR;
  }

  /* This should probably be in a loop (locks) */
  data = get_otp_data(db, &user);
  if (data == NULL) {
    DBG("The user didn't match")
    return OTP_ERR;
  }

  /* Check Pub_ID */
  if (memcmp(data->pubid, otp, OTP_PUB_ID_HEX_LEN)) {
    DBG("No corresponding Public ID")
    free_otp_data(data);
    return OTP_ERR;
  }

  /* Init AES */
  key = aes_init(data->key);
  if (key == NULL) {
    DBG("Unable to initialize AES sub-system")
    free_otp_data(data);
    return OTP_ERR;
  }

  /* Decrypt OTP */
  otp_dec = extract_otp(otp + OTP_PUB_ID_HEX_LEN, key);
  if (otp_dec == NULL) {
    DBG("Decryption error")
    free_otp_data(data);
    return OTP_ERR;
  }

  /* Verify Priv_id */
  priv_id = hex2bin(data->privid_hash, strlen(data->privid_hash));
  ret = check_hash(data->digest_name, otp_dec->private_id, OTP_PRIVID_BIN_LEN, priv_id, strlen(data->privid_hash) / 2);
  if (ret != 0) {
    DBG("Bad Private ID")
    free(otp_dec);
    free(priv_id);
    free_otp_data(data);
    return OTP_ERR;
  }
  free_otp_data(data);
  free(priv_id);

  /* Verify CRC16 */
  if(crc16((uint8_t*) otp_dec, OTP_BIN_LEN) != OTP_CRC) {
    DBG("Bad CRC")
    free(otp_dec);
    return OTP_ERR;
  }

  for (temp = 0; temp < MAX_RETRIES; ++temp) {

    /* Try to get lock on database and key info */
    ret = try_get_credentials(db, &store, &user);

    switch (ret) {
      case OTP_SQL_OK:
        /* Verify that the OTP is new */
        if ((store.session_counter < otp_dec->session_counter)
            || ((store.session_counter == otp_dec->session_counter)
              && (store.timecode < (((unsigned int)otp_dec->timecode_high) << 16) + ((unsigned int)otp_dec->timecode_low)))) {
          store.session_counter = otp_dec->session_counter;
          store.timecode = (unsigned int) (otp_dec->timecode_high << 16) + otp_dec->timecode_low;
          /* Store new OTP state */
          ret = try_update_credentials(db, &store, &user);
          if (ret == OTP_SQL_OK) {
            aes_clean(key);
            sql_close(db);
            free(otp_dec);
            return OTP_OK;
          } else if (ret == OTP_SQL_ERR) {
            DBG("SQL error")
            aes_clean(key);
            sql_close(db);
            free(otp_dec);
            return OTP_ERR;
          }
        } else {
          DBG("OTP replayed ")
          rollback(db);
          aes_clean(key);
          sql_close(db);
          free(otp_dec);
          return OTP_ERR;
        }
        break;
      case OTP_SQL_ERR:
        DBG("SQL error")
        aes_clean(key);
        sql_close(db);
        free(otp_dec);
        return OTP_ERR;
      case OTP_SQL_MAY_RETRY:
        break;
    }
  }

  free(otp_dec);
  return OTP_ERR;
}
