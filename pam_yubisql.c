#define PAM_SM_AUTH

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

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
#include "debug.h"

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#define PAM_PRINTF(...)                 \
  SYSTEM_PRINTF(verbose,  __VA_ARGS__)

#define IF_NOT_RET(...)     \
  if (ret != PAM_SUCCESS) { \
    PAM_PRINTF(__VA_ARGS__) \
    return PAM_AUTH_ERR;    \
  }

static int
vfork_vrap(const char *child_exec, const char * const * argv, int verbose)
{
  int child = vfork();
  if (child == 0) {
    execv(child_exec, (char *const*) argv);
    PAM_PRINTF("Execv error: %i (%s)\n", errno, strerror(errno))
    _exit(-1);
  }
  return child;
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
  const char* last_unknown_option = NULL;

  /* State */
  int i, ret;
  const char* user;
  size_t user_len;
  const char* input = NULL;
  size_t input_len;
  const char* otp;
  char* password;
  pid_t child;

  /* Extract the options */
  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "exec=", 5ul) == 0) {
      slave_exec = (const char *) argv[i] + 5;
    } else if (strncmp(argv[i], "sql_db=", 7ul) == 0) {
      sql_db = (const char *) argv[i] + 7;
    } else if (strcmp(argv[i], "debug") == 0) {
      verbose = 1;
    } else if (strcmp(argv[i], "try_first_pass") == 0) {
      try_first_pass = 1;
    } else {
      /* If already verbose, print any unknown option */
      PAM_PRINTF("Unknown option: '%s'\n", argv[i])
      else {
        /* At least count the unknown options */
        ++unknown_options;
        last_unknown_option = argv[i];
      }
    }
  }

  /* If we didn't warned about some unknown options but we are verbose, do it now */
  if (unknown_options && (last_unknown_option != NULL)) {
    PAM_PRINTF("%i options were lost during the option processing\n", unknown_options);
    PAM_PRINTF("Last of them: %s\n", last_unknown_option);
  }

  if (sql_db == NULL) {
    PAM_PRINTF("No database, abort\n")
    return PAM_AUTH_ERR;
  }

  /* Get the user */
  ret = pam_get_user(pamh, &user, NULL);
  IF_NOT_RET("pam_get_user failed with return %i\n", ret)
  user_len = strlen(user);

  /* If try_first_pass is set, let's try to optain it */
  if (try_first_pass) {
    ret = pam_get_item(pamh, PAM_AUTHTOK, (void *) &input);
    IF_NOT_RET("pam_get_user failed with return %i\n", ret)
    PAM_PRINTF("pam_get_user succeded\n")
  }

  /* If we still have not input, we need to find it */
  if (input == NULL) {
    struct pam_conv *conv;
    struct pam_message message;
    const struct pam_message *message_p;
    struct pam_response *response = NULL;

    /* Get pam_conv */
    ret = pam_get_item(pamh, PAM_CONV, (void*) &conv);
    IF_NOT_RET("pam_get_item(PAM_CONV) failed with return %i\n", ret)

    /* Construct message */
    char *message_content = calloc(1ul, 15ul + user_len);
    snprintf(message_content, 15ul + user_len, "Yubikey for %s: ", user);
    message.msg = message_content;
    message.msg_style = PAM_PROMPT_ECHO_OFF;

    /* Put the enveloppe */
    message_p = &message;

    /* Send */
    ret = conv->conv(1, &message_p, &response, conv->appdata_ptr);

    /* We can already drop our message */
    free(message_content);

    /* Success ? */
    IF_NOT_RET("Conversation failure: unable to get password (%i:%s)\n", ret, pam_strerror(pamh, ret));
    if ((response == NULL) || (response->resp == NULL)) {
      PAM_PRINTF("Conversation failure: NULL response (%p)!\n", response)
      return PAM_AUTH_ERR;
    }

    input = response->resp;
    free(response);
  }

  /* Separate password from otp if any */
  input_len = strlen(input);
  /* Big enough ? */
  if (strlen(input) < OTP_MESSAGE_HEX) {
    PAM_PRINTF("Input too short to be useful\n")
    return PAM_AUTH_ERR;
  }
  if (strlen(input) > OTP_MESSAGE_HEX) {
    /* Extract password */
    password = calloc(1ul, input_len + 1ul - OTP_MESSAGE_HEX);
    if (password == NULL) {
      PAM_PRINTF("Malloc error\n")
      return PAM_AUTH_ERR;
    }
    strncpy(password, input, input_len - OTP_MESSAGE_HEX);
    /* Transmit password to childs */
    ret = pam_set_item(pamh, PAM_AUTHTOK, password);
    free(password);
    IF_NOT_RET("pam_set_item(PAM_AUTHTOK) failed with return %i\n", ret)
  }
  otp = input + (input_len - OTP_MESSAGE_HEX);

  /* Create helper argv */
  const char * helper_argv[] = {slave_exec, "-s", sql_db, "-u", user, "-o", otp, NULL};
  if (verbose) {
    helper_argv[1] = "-vls";
  }

  /* Invoque helper */
  child = vfork_vrap(slave_exec, helper_argv, verbose);

  if (child <= 0) {
    PAM_PRINTF("Fork error\n");
    return PAM_AUTH_ERR;
  }

  if (waitpid(child, &ret, 0) < 0 ) {
    PAM_PRINTF("Error while waiting for helper\n")
    return PAM_AUTH_ERR;
  }
  if (WIFSIGNALED(ret)) {
    PAM_PRINTF("Child killed: signal %d%s\n", WTERMSIG(ret), WCOREDUMP(ret) ? " - core dumped" : "");
    return PAM_AUTH_ERR;
  }
  if(WIFEXITED(ret)) {
    ret = WEXITSTATUS(ret);
    IF_NOT_RET("Bad OTP\n");
    PAM_PRINTF("Success\n")
    return PAM_SUCCESS;
  }
  PAM_PRINTF("Child error\n")
  return PAM_AUTH_ERR;
}

#ifdef PAM_STATIC
# ifdef OPENPAM
PAM_MODULE_ENTRY("pam_yubisql")
# else /* OPENPAM */
struct pam_module _pam_yubico_modstruct = {
  "pam_yubisql",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
# endif /* OPENPAM */
#endif /* PAM_STATIC */

