/*
 *  megatools - Mega.co.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "tools.h"

static gboolean opt_register;
static gchar* opt_verify;
static gchar* opt_state;
static gchar* opt_name;
static gchar* opt_email;
static gchar* opt_password;
static gboolean opt_anonymous;
static gboolean opt_script;
static gboolean opt_agree;

static GOptionEntry entries[] =
{
  { "verify",      'v',   0, G_OPTION_ARG_STRING,  &opt_verify,     "Finish registration",                           "LINK"       },
  { "anonymous",   'a',   0, G_OPTION_ARG_NONE,    &opt_anonymous,  "Create new anonymous account",                  NULL         },
  { "state",       '\0',  0, G_OPTION_ARG_STRING,  &opt_state,      "Registration state information",                "STATE"      },
  { "name",        'n',   0, G_OPTION_ARG_STRING,  &opt_name,       "Your real name",                                "NAME"       },
  { "email",       'e',   0, G_OPTION_ARG_STRING,  &opt_email,      "Your email (will be your username)",            "EMAIL"      },
  { "password",    'p',   0, G_OPTION_ARG_STRING,  &opt_password,   "Your password",                                 "PASSWORD"   },
  { "script",      's',   0, G_OPTION_ARG_NONE,    &opt_script,     "Return script friendly output from --register", NULL         },
  { "agree",       '\0',  0, G_OPTION_ARG_NONE,    &opt_agree,      "Pass this option if you agree with Mega.co.nz TOS", NULL     },
  { NULL }
};

static gchar* parse_signup_key(const gchar* text)
{
  gchar* signup_key = NULL;
  GMatchInfo* m = NULL;
  GRegex* r;
  
  r = g_regex_new("(?:https?://mega.co.nz/#confirm)?([a-z0-9_-]{80,150})", G_REGEX_CASELESS, 0, NULL);
  g_assert(r != NULL);

  if (!g_regex_match(r, text, 0, &m))
  {
    g_match_info_unref(m);
    g_regex_unref(r);
    return NULL;
  }

  signup_key = g_match_info_fetch(m, 1);
  g_match_info_unref(m);
  g_regex_unref(r);

  return signup_key;
}

static void do_verify(void)
{
  GError *local_err = NULL;
  MegaSession* s;
  gchar* signup_key = parse_signup_key(opt_verify);

  if (!signup_key)
  {
    g_printerr("ERROR: Invalid verification link or key: '%s'\n", opt_verify);
    exit(1);
  }

  s = mega_session_new();

  if (!mega_session_register_verify(s, opt_state, signup_key, &local_err))
  {
    if (g_error_matches(local_err, MEGA_API_ERROR, MEGA_API_ERROR_EARGS)) // 'us' returns EARGS if account was already verified
      g_printerr("ERROR: Verification failed: Account is already verified\n");
    else
      g_printerr("ERROR: Verification failed: %s\n", local_err ? local_err->message : "Unknown error");
    g_clear_error(&local_err);
    tool_fini(s);
    exit(1);
  }

  if (!opt_script)
    g_print("The account was registered successfully!\n");

  tool_fini(s);
  exit(0);
}

static void do_register(void)
{
  GError *local_err = NULL;
  MegaSession* s;

  s = mega_session_new();

  gchar* state = mega_session_register(s, opt_email, opt_password, opt_name, &local_err);
  if (!state)
  {
    if (g_error_matches(local_err, MEGA_API_ERROR, MEGA_API_ERROR_EEXIST))
      g_printerr("ERROR: Account '%s' already exists\n", opt_email);
    else
      g_printerr("ERROR: Registration failed: %s\n", local_err ? local_err->message : "Unknown error");
    g_clear_error(&local_err);
    tool_fini(s);
    exit(1);
  }

  if (opt_script)
  {
    g_print("megareg --state \"%s\" --verify \n", state);
  }
  else
  {
    if (tool_is_interactive())
    {
      g_print("Registration email was sent to '%s'.\nTo complete registration, enter signup link bellow.\n\n", opt_email);
      while (TRUE)
      {
        gchar* link = tool_prompt(TRUE, "Enter signup link for %s, or press CTRL+C", opt_email);
        if (!link)
          break;

        gchar* signup_key = parse_signup_key(link);
        if (!signup_key)
        {
          g_print("Invalid verification key or link. Please try again.\n");
          continue;
        }

        mega_session_close(s);

        if (!mega_session_register_verify(s, state, signup_key, &local_err))
        {
          g_printerr("ERROR: Verification failed: %s\n", local_err ? local_err->message : "Unknown error");
          g_clear_error(&local_err);
          tool_fini(s);
          exit(1);
        }

        g_print("The account was registered successfully!\n");
        tool_fini(s);
        exit(0);
      }
    }

    g_print(
      "Registration email was sent to %s. To complete registration, you must run:\n\n"
      "  megareg --state \"%s\" --verify \"LINK\"\n\n"
      "(Where LINK is registration link from the 'MEGA Signup' email)\n",
      opt_email,
      state
    );
  }

  tool_fini(s);
  exit(0);
}

static void do_register_anonymous(void)
{
  GError *local_err = NULL;
  MegaSession* s;

  s = mega_session_new();

  gchar* user_handle = mega_session_register_anon(s, opt_password, &local_err);
  if (!user_handle)
  {
    g_printerr("ERROR: Registration failed: %s\n", local_err ? local_err->message : "Unknown error");
    g_clear_error(&local_err);
    tool_fini(s);
    exit(1);
  }

  if (opt_script)
    g_print("%s\n", user_handle);
  else
    g_print("New anonymous account was registered with user handle '%s'\n", user_handle);

  tool_fini(s);
  exit(0);
}

#define ASSERT_OPTION(expr, msg) \
  G_STMT_START { \
    if (!(expr)) { \
      g_printerr("ERROR: " msg "\n"); \
      exit(1); \
    } \
  } G_STMT_END

int main(int ac, char* av[])
{
  tool_init_bare(&ac, &av, " - register a new mega.co.nz account", entries);

  if (opt_verify)
  {
    ASSERT_OPTION(opt_state, "--state option is required");
    ASSERT_OPTION(!opt_anonymous, "--anonymous option conflicts with --verify");
    ASSERT_OPTION(!opt_password, "--password option conflicts with --verify");
    ASSERT_OPTION(!opt_name, "--name option conflicts with --verify");
    ASSERT_OPTION(!opt_email, "--email option conflicts with --verify");

    do_verify();
  }

  if (!opt_agree)
  {
    g_printerr("You must read and agree to Mega.co.nz terms of service available at:\n\n  http://g.static.mega.co.nz/pages/terms.html\n\n");
    return 1;
  }

  if (opt_anonymous)
  {
    ASSERT_OPTION(!opt_state, "--state option conflicts with --anonymous");
    ASSERT_OPTION(!opt_name, "--name option conflicts with --anonymous");
    ASSERT_OPTION(!opt_email, "--email option conflicts with --anonymous");
    ASSERT_OPTION(opt_password, "--password option is required");

    do_register_anonymous();
  }

  ASSERT_OPTION(!opt_state, "--state option should not be used for registration");
  ASSERT_OPTION(opt_name, "--name option is required");
  ASSERT_OPTION(opt_email, "--email option is required");
  ASSERT_OPTION(is_email_valid(opt_email), "Email address is invalid");
  ASSERT_OPTION(opt_password, "--password option is required");
  ASSERT_OPTION(strlen(opt_password) > 0, "Password can't be empty");

  do_register();

  return 1;
}
