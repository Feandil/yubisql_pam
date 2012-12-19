#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "otp.h"

#define DEFAULT_DIGEST "sha512"
#define MAX_RETRIES 3
#define DIGEST_NAME_MAX_SIZE 20

static void
usage(int err)
{
  if (err > 0) {
    switch(err) {
      case 1:
        printf("Too many arguments\n");
        break;
      case 2:
        printf("Database not set\n");
        break;
      case 3:
        printf("User not set\n");
        break;
      case 4:
        printf("Public ID not set\n");
        break;
      case 5:
        printf("Private ID not set\n");
        break;
      case 6:
        printf("AES key not set\n");
        break;
      case 7:
        printf("Option missmatch: should be used with -a\n");
        break;
      default:
        printf("Unknown usage error (%i), please contact us\n", err);
        exit(-2);
        break;
    }
  } else {
    printf("manage_OTP: User interface to the database storing the yubikey informations\n");
    printf("   (Package: %s. Bug report to %s)\n\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    printf("Usage: ./manage_OTP [-hv] -s <database> [-lcagr] [sub-obtions]\n");
    printf("        Exit code specifies the result: 0 = OK, !0 = ERROR\n");
    printf("Options:\n");
    printf(" -h, --help                 Print this ...\n");
    printf("Modules:\n");
    printf(" -l                         List the registered users\n");
    printf(" -c                         Create a new database\n");
    printf(" -g <username>              Get the credentials for the <username>\n");
    printf(" -a <username>              Create new credentials for <username>:\n");
    printf("                              Interactively asks for the information\n");
    printf(" -r <username>              Delete the credentials for <username>:\n");

    exit(err);
  }
  exit(-1);
}

enum manage_action {
  MANAGE_ACTION_HELP,
  MANAGE_ACTION_LIST,
  MANAGE_ACTION_CREATE,
  MANAGE_ACTION_GET,
  MANAGE_ACTION_ADD,
  MANAGE_ACTION_DELETE
};

static int
read_input_word(char *buf, int len, const char* name)
{
  char *temp;
  printf("Please enter the %s\n", name);
  temp = fgets(buf, len, stdin);
  if (temp == NULL) {
    printf("Unable to read input\n");
  }
  if (buf[len - 1] != 0) {
    printf("%s too short (%c(%i)), please retry\n", name, buf[len - 1], buf[len - 1]);
    return -1;
  }
  buf[len - 1] = (char) getc(stdin);
  if (getc(stdin) != '\n') {
    printf("%s too long, please retry\n", name);
    return -1;
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  char *sql_db = NULL;
  sqlite3* db;
  char *username = NULL;
  struct user user;
  enum manage_action action = MANAGE_ACTION_HELP;
  int opt;
  char privid[OTP_PRIVID_HEX_LEN];
  unsigned char *privid_bin;
  int temp, ret;
  struct otp_data* data;
  char digest_name[DIGEST_NAME_MAX_SIZE];
  char *ctemp;

  while((opt = getopt(argc, argv, "hs:lg:r:a:c")) != -1) {
    switch(opt) {
      case 'h':
        usage(0);
        break;
      case 's':
        sql_db = optarg;
        break;
      case 'l':
        if (action != MANAGE_ACTION_HELP) {
          usage(1);
        }
        action = MANAGE_ACTION_LIST;
        break;
      case 'g':
        if (action != MANAGE_ACTION_HELP) {
          usage(1);
        }
        action = MANAGE_ACTION_GET;
        username = optarg;
        break;
      case 'r':
        if (action != MANAGE_ACTION_HELP) {
          usage(1);
        }
        action = MANAGE_ACTION_DELETE;
        username = optarg;
        break;
      case 'a':
        if (action != MANAGE_ACTION_HELP) {
          usage(1);
        }
        action = MANAGE_ACTION_ADD;
        username = optarg;
        break;
      case 'c':
        if (action != MANAGE_ACTION_HELP) {
          usage(1);
        }
        action = MANAGE_ACTION_CREATE;
        break;
      default:
        usage(0);
     }
  }

  if(argc > optind) {
    usage(1);
  }

  if (action == MANAGE_ACTION_HELP) {
    usage(0);
  }

  if (sql_db == NULL) {
    usage(2);
  }

  db = init(sql_db);
  if (db == NULL) {
    printf("Unable to open the database\n");
    return 1;
  }
  switch(action) {
    case MANAGE_ACTION_HELP:
       /* Already done */
      break;
    case MANAGE_ACTION_LIST:
      list_users(db);
      sql_close(db);
      return 0;
    case MANAGE_ACTION_CREATE:
      create_database(db);
      return 0;
    case MANAGE_ACTION_GET:
    case MANAGE_ACTION_ADD:
    case MANAGE_ACTION_DELETE:
      /* Later */
      break;
  }
  if (username == NULL) {
    usage(3);
  }
  if (verify_user(username, strlen(username), &user) != 0) {
    printf("Unauthorized char in the username");
    return OTP_ERR;
  }

  switch(action) {
    case MANAGE_ACTION_HELP:
    case MANAGE_ACTION_LIST:
    case MANAGE_ACTION_CREATE:
      /* Already done */
      break;
    case MANAGE_ACTION_GET:
      data = get_otp_data(db, &user);
      if (data == NULL) {
        printf("No such user\n");
        break;
      }
      printf("User '%.*s':\n", (unsigned int) user.len, user.name);
      printf("Public ID  : %.*s\n", (int) OTP_PUB_ID_HEX_LEN, data->pubid);
      printf("Private Key: %.*s\n", (int) OTP_KEY_HEX_LEN, data->key);
      printf("Private ID digest: %s\n", data->digest_name);
      printf("Private ID hash:   %s\n", data->privid_hash);
      free(data);
      break;
    case MANAGE_ACTION_DELETE:
      for (temp = 0; temp < MAX_RETRIES; ++temp) {
        ret = try_start_transaction(db);
        switch (ret) {
          case OTP_SQL_ERR:
            printf("SQL error during the transaction initialisation");
            goto free_db;
          case OTP_SQL_MAY_RETRY:
            break;
          case OTP_SQL_OK:
            ret = try_delete_credentials(db, &user);
            switch (ret) {
              case OTP_SQL_ERR:
                printf("SQL error while trying to remove user");
                goto free_db;
              case OTP_SQL_MAY_RETRY:
                break;
              case OTP_SQL_OK:
                ret = try_end_transaction(db);
                switch (ret) {
                  case OTP_SQL_MAY_RETRY:
                    break;
                  case OTP_SQL_ERR:
                    printf("SQL error when trying to commit the transaction");
                    goto free_db;
                  case OTP_SQL_OK:
                    sql_close(db);
                    return 0;
                }
            }
        }
      }
      printf("Unable to remove user (Database busy)\n");
      break;
    case MANAGE_ACTION_ADD:
      data = calloc(sizeof(struct otp_data), 1);
      if (data == NULL) {
        printf("Malloc error\n");
        goto free_db;
      }
      if (read_input_word(data->pubid, OTP_PUB_ID_HEX_LEN, "Public ID")) {
        goto free_data;
      }
      if (check_modhex(data->pubid, OTP_PUB_ID_HEX_LEN) != 0) {
        printf("Non hex character in input, please retry\n");
        goto free_data;
      }

      if (read_input_word(data->key, OTP_KEY_HEX_LEN, "AES key")) {
        goto free_data;
      }
      if (check_hex(data->key, OTP_KEY_HEX_LEN) != 0) {
        printf("Non hex character in input, please retry\n");
        goto free_data;
      }

      if (read_input_word(privid, OTP_PRIVID_HEX_LEN, "Private ID")) {
        goto free_data;
      }
      if (check_hex(privid, OTP_PRIVID_HEX_LEN) != 0) {
        printf("Non hex character in input, please retry\n");
        goto free_data;
      }
      privid_bin = hex2bin(privid, OTP_PRIVID_HEX_LEN);
      if (privid_bin == NULL) {
        printf("Malloc error (bis)\n");
        goto free_data;
      }

      printf("Please Specify a valid digest algorithm [%s]\n", DEFAULT_DIGEST);
      memset(digest_name, 0, DIGEST_NAME_MAX_SIZE);
      ctemp = fgets(digest_name, DIGEST_NAME_MAX_SIZE, stdin);
      if (ctemp == NULL) {
        printf("Unable to read input\n");
        goto free_data;
      }
      if (digest_name[DIGEST_NAME_MAX_SIZE - 1] != 0 && digest_name[DIGEST_NAME_MAX_SIZE - 1] != '\n') {
        printf("Digest algorithm name too long, please retry\n");
        goto free_data;
      }
      if (digest_name[0] == '\n') {
        data->digest_name = strdup(DEFAULT_DIGEST);
      } else {
        ctemp = memchr(digest_name, '\n', DIGEST_NAME_MAX_SIZE);
        if (ctemp != NULL) {
          *ctemp = '\0';
        }
        data->digest_name = digest_name;
      }
      ctemp = (char*)compute_hash(data->digest_name, (char*)privid_bin, OTP_PRIVID_BIN_LEN);
      if (ctemp == NULL) {
        goto free_data;
      }
      data->privid_hash = bin2hex(ctemp, strlen(ctemp));
      if (data->privid_hash == NULL) {
        goto free_data;
      }
      printf("New user :\n");
      printf("Name: '%.*s':\n", (unsigned int) user.len, user.name);
      printf("Public ID  : %.*s\n", (int) OTP_PUB_ID_HEX_LEN, data->pubid);
      printf("Private Key: %.*s\n", (int) OTP_KEY_HEX_LEN, data->key);
      printf("Private ID:        %.*s\n", (int) OTP_PRIVID_HEX_LEN, privid);
      printf("Private ID digest: %s\n", data->digest_name);
      printf("Private ID hash:   %s\n", data->privid_hash);
      printf("Press enter to create this new user\n");
      if (getc(stdin) != '\n') {
        goto free_data;
      }
      for (temp = 0; temp < MAX_RETRIES; ++temp) {
        ret = try_start_transaction(db);
        switch (ret) {
          case OTP_SQL_ERR:
            printf("SQL error during the transaction initialisation");
            goto free_data;
          case OTP_SQL_MAY_RETRY:
            break;
          case OTP_SQL_OK:
            ret = try_create_credentials(db, data, &user);
            switch (ret) {
              case OTP_SQL_ERR:
                printf("SQL error while trying to add the user");
                goto free_data;
              case OTP_SQL_MAY_RETRY:
                break;
              case OTP_SQL_OK:
                ret = try_end_transaction(db);
                switch (ret) {
                  case OTP_SQL_MAY_RETRY:
                    break;
                  case OTP_SQL_ERR:
                    printf("SQL error when trying to commit the transaction");
                    goto free_data;
                  case OTP_SQL_OK:
                    goto free_data;
                }
            }
        }
      }
      printf("Unable to create user (Database busy)\n");
      break;
  }
  goto free_db;

free_data:
  free_otp_data(data);
free_db:
  sql_close(db);
  return 0;
}
