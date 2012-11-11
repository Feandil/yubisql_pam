#define PAM_SM_AUTH

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef PIC
# define PAM_STATIC
#endif /* PIC */

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PAM_EXTERN
# ifdef PAM_STATIC
#  define PAM_EXTERN static
# else /* PAM_STATIC */
#  define PAM_EXTERN extern
# endif /* PAM_STATIC */
#endif /* PAM_EXTERN */

#include "otp.h"

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#define PRINTF(...)       \
  if (verbose) {          \
    printf(__VA_ARGS__);  \
  }

#define IF_NOT_RET(...)     \
  if (ret != PAM_SUCCESS) { \
    PRINTF(__VA_ARGS__);    \
    return PAM_AUTH_ERR;    \
  }


PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char** argv)
{
  /* Configuration */
  char verbose = 0;
  char try_first_pass = 0;
  const char *slave_exec = "/usr/bin/check_OTP";
  const char *sql_db = NULL;
  int unknown_options = 0;
  const char* last_unknown_option;

  /* State */
  int i, ret;
  const char* user;
  size_t user_len;
  const char* input = NULL;
  size_t input_len;
  const char* otp;
  char* password;

  /* Extract the options */
  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "exec=", 5) == 0) {
      slave_exec = (const char *) argv[i] + 5;
    } else if (strncmp(argv[i], "sql_db=", 7) == 0) {
      sql_db = (const char *) argv[i] + 7;
    } else if (strcmp(argv[i], "debug") == 0) {
      verbose = 1;
    } else if (strcmp(argv[i], "try_first_pass") == 0) {
      try_first_pass = 1;
    } else {
      /* If already verbose, print any unknown option */
      PRINTF("Unknown option: '%s'\n", argv[i])
      else {
        /* At least count the unknown options */
        ++unknown_options;
        last_unknown_option = argv[i];
      }
    }
  }

  /* If we didn't warned about some unknown options but we are verbose, do it now */
  if (verbose && unknown_options) {
    printf("%i options were lost during the option processing\n", unknown_options);
    printf("Last of them: %s\n", last_unknown_option);
  }

  if (sql_db == NULL) {
    PRINTF("No database, abort\n")
    return PAM_AUTH_ERR;
  }

  /* Get the user */
  ret = pam_get_user(pamh, &user, NULL);
  IF_NOT_RET("pam_get_user failed with return %i\n", ret)
  user_len = strlen(user);

  /* If try_first_pass is set, let's try to optain it */
  if (try_first_pass) {
    ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &input);
    IF_NOT_RET("pam_get_user failed with return %i\n", ret)
    PRINTF("pam_get_user succeded\n")
  }

  /* If we still have not input, we need to find it */
  if (input == NULL) {
    struct pam_conv *conv;
    struct pam_message message;
    const struct pam_message *message_p;
    struct pam_response *response;

    /* Get pam_conv */
    ret = pam_get_item(pamh, PAM_CONV, (const void**) &conv);
    IF_NOT_RET("pam_get_item(PAM_CONV) failed with return %i\n", ret)

    /* Construct message */
    char *message_content = calloc(1, 15 + user_len);
    snprintf(message_content, 15 + user_len, "Yubikey for %s: ", user);
    message.msg = message_content;
    message.msg_style = PAM_PROMPT_ECHO_ON;

    /* Put the enveloppe */
    message_p = &message;

    /* Send */
    ret = conv->conv(1, &message_p, &response, conv->appdata_ptr);

    /* We can already drop our message */
    free(message_content);

    /* Success ? */
    IF_NOT_RET("Conversation failure: unable to get password (%i)\n", ret);
    if ((response == NULL) || (response->resp == NULL)) {
      PRINTF("Conversation failure: NULL response !\n")
      return PAM_AUTH_ERR;
    }

    input = response->resp;
    free(response);
  }

  /* Separate password from otp if any */
  input_len = strlen(input);
  /* Big enough ? */
  if (strlen(input) < OTP_MESSAGE_HEX) {
    PRINTF("Input too short to be useful\n")
    return PAM_AUTH_ERR;
  }
  if (strlen(input) > OTP_MESSAGE_HEX) {
    /* Extract password */
    password = calloc(1, input_len + 1 - OTP_MESSAGE_HEX);
    if (password == NULL) {
      PRINTF("Malloc error\n")
      return PAM_AUTH_ERR;
    }
    strncpy(password, input, input_len - OTP_MESSAGE_HEX);
    /* Transmit password to childs */
    ret = pam_set_item(pamh, PAM_AUTHTOK, password);
    free(password);
    IF_NOT_RET("pam_set_item(PAM_AUTHTOK) failed with return %i\n", ret)
  }
  otp = input + (input_len - OTP_MESSAGE_HEX);

  /* Invoque helper */
  if (verbose) {
    const char * const helper_argv[] = {slave_exec, "-s", sql_db, "-u", user, "-o", otp, NULL};
    ret = execv(slave_exec, (char *const*) helper_argv);
  } else {
    const char * const helper_argv[] = {slave_exec, "-v", "-s", sql_db, "-u", user, "-o", otp, NULL};
    ret = execv(slave_exec, (char *const*) helper_argv);
  }
  if (ret == -1) {
    PRINTF("Execv error, file not found ?\n")
    return PAM_AUTH_ERR;
  }
  IF_NOT_RET("Bad OTP")

  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_yubico_modstruct = {
  "pam_yubisql",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};

#endif /* PAM_STATIC */
