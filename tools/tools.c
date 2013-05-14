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

#include <locale.h>

#include "config.h"
#include "tools.h"

#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#endif

#ifdef G_OS_WIN32
#define MEGA_RC_FILENAME "mega.ini"
#else
#define MEGA_RC_FILENAME ".megarc"
#endif

static GOptionContext* opt_context;
static gchar* opt_username;
static gchar* opt_password;
static gchar* opt_config;
static gboolean opt_reload_files;
static gint opt_cache_timout = 10 * 60;
static gboolean opt_version;
static gboolean opt_no_config;
static gboolean opt_no_ask_password;
gboolean tool_allow_unknown_options = FALSE;
guint tool_debug = 0;

static gboolean opt_debug_callback(const gchar *option_name, const gchar *value, gpointer data, GError **error)
{
  if (value)
  {
    gchar** opts = g_strsplit(value, ",", 0);
    gchar** opt = opts;

    while (*opt)
    {
      if (g_ascii_strcasecmp(*opt, "api") == 0)
        tool_debug |= DEBUG_API;
      else if (g_ascii_strcasecmp(*opt, "fs") == 0)
        tool_debug |= DEBUG_FS;
      else if (g_ascii_strcasecmp(*opt, "cache") == 0)
        tool_debug |= DEBUG_CACHE;

      opt++;
    }
  }
  else
  {
    tool_debug = DEBUG_API;
  }

  return TRUE;
}

static GOptionEntry basic_options[] =
{
  { "debug",              '\0',  G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, opt_debug_callback, "Enable debugging output", "OPTS"  },
  { "version",            '\0',  0, G_OPTION_ARG_NONE,    &opt_version,      "Show version information",           NULL    },
  { NULL }
};

static GOptionEntry auth_options[] =
{
  { "username",            'u',  0, G_OPTION_ARG_STRING,  &opt_username,        "Account username (email)",               "USERNAME" },
  { "password",            'p',  0, G_OPTION_ARG_STRING,  &opt_password,        "Account password",                       "PASSWORD" },
  { "config",             '\0',  0, G_OPTION_ARG_STRING,  &opt_config,          "Load configuration from a file",         "PATH"     },
  { "ignore-config-file", '\0',  0, G_OPTION_ARG_NONE,    &opt_no_config,       "Disable loading " MEGA_RC_FILENAME,      NULL       },
  { "no-ask-password",    '\0',  0, G_OPTION_ARG_NONE,    &opt_no_ask_password, "Never ask interactively for a password", NULL       },
  { "reload",             '\0',  0, G_OPTION_ARG_NONE,    &opt_reload_files,    "Reload filesystem cache",                NULL       },
  { NULL }
};

#ifdef G_OS_WIN32
static gchar* get_tools_dir(void)
{
  gchar *path = NULL;
  wchar_t *wpath;
  DWORD len = PATH_MAX;

  HMODULE handle = GetModuleHandleW(NULL);

  wpath = g_new0(wchar_t, len);
  if (GetModuleFileNameW(handle, wpath, len) < len)
    path = g_utf16_to_utf8(wpath, -1, NULL, NULL, NULL);
  g_free(wpath);

  if (path == NULL)
    path = g_strdup("");

  gchar* dir = g_path_get_dirname(path);
  g_free(path);
  return dir;
}
#endif

static void init(void)
{
#if !GLIB_CHECK_VERSION(2, 32, 0)
  if (!g_thread_supported())
    g_thread_init(NULL);
#endif

  setlocale(LC_ALL, "");

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

#ifndef G_OS_WIN32
  //XXX: is this still necessary with GIO?
  signal(SIGPIPE, SIG_IGN);
#endif

#ifdef G_OS_WIN32
  gchar* tools_dir = get_tools_dir();

  gchar* tmp = g_build_filename(tools_dir, "gio", NULL);
  g_setenv("GIO_EXTRA_MODULES", tmp, TRUE);
  g_free(tmp);

  gchar* certs = g_build_filename(tools_dir, "ca-certificates.crt", NULL);
  g_setenv("CA_CERT_PATH", certs, TRUE);
  g_free(certs);

  g_free(tools_dir);
#endif
}

static gchar* input_password(void)
{
  gint tries = 3;
  gchar buf[256];
  gchar* password = NULL;

#ifdef G_OS_WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
  DWORD mode = 0;
  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else
  struct termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  struct termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif

again:
  g_print("Enter password for (%s): ", opt_username);
  if (fgets(buf, 256, stdin))
  {
    if (strlen(buf) > 1)
    {
      password = g_strndup(buf, strcspn(buf, "\r\n"));
    }
    else
    {
      if (--tries > 0)
      {
        g_print("\n");
        goto again;
      }

      g_print("\nYou need to provide non-empty password!\n");
      exit(1);
    }
  }
  else
  {
    g_printerr("\nERROR: Can't read password from the input!\n");
    exit(1);
  }

#ifdef G_OS_WIN32
  SetConsoleMode(hStdin, mode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

  g_print("\nGood, signing in...\n");

  return password;
}

static void print_version(void)
{
  if (opt_version)
  {
    g_print("megatools " VERSION " - command line tools for Mega.co.nz\n\n");
    g_print("Written by Ondřej Jirman <megous@megous.com>, 2013\n");
    g_print("Go to http://megatools.megous.com for more information\n");
    exit(0);
  }
}

void tool_init_bare(gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries)
{
  GError *local_err = NULL;

  init();

  opt_context = g_option_context_new(tool_name);
  if (tool_allow_unknown_options)
    g_option_context_set_ignore_unknown_options(opt_context, TRUE);
  if (tool_entries)
    g_option_context_add_main_entries(opt_context, tool_entries, NULL);
  g_option_context_add_main_entries(opt_context, basic_options, NULL);

  if (!g_option_context_parse(opt_context, ac, av, &local_err))
  {
    g_printerr("ERROR: Option parsing failed: %s\n", local_err->message);
    g_clear_error(&local_err);
    exit(1);
  }

  print_version();
}

void tool_init(gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries)
{
  GError *local_err = NULL;

  init();

  opt_context = g_option_context_new(tool_name);
  if (tool_allow_unknown_options)
    g_option_context_set_ignore_unknown_options(opt_context, TRUE);
  if (tool_entries)
    g_option_context_add_main_entries(opt_context, tool_entries, NULL);
  g_option_context_add_main_entries(opt_context, auth_options, NULL);
  g_option_context_add_main_entries(opt_context, basic_options, NULL);

  if (!g_option_context_parse(opt_context, ac, av, &local_err))
  {
    g_printerr("ERROR: Option parsing failed: %s\n", local_err->message);
    g_clear_error(&local_err);
    exit(1);
  }

  print_version();

  // load username/password from ini file
  if (!opt_no_config || opt_config)
  {
    GKeyFile* kf = g_key_file_new();
    gchar* tmp = g_build_filename(g_get_home_dir(), MEGA_RC_FILENAME, NULL);
    gboolean status;

    if (opt_config)
      status = g_key_file_load_from_file(kf, opt_config, 0, NULL);
    else
      status = g_key_file_load_from_file(kf, tmp, 0, NULL) || g_key_file_load_from_file(kf, MEGA_RC_FILENAME, 0, NULL);

    if (status)
    {
      if (!opt_username)
        opt_username = g_key_file_get_string(kf, "Login", "Username", NULL);
      if(!opt_password)
        opt_password = g_key_file_get_string(kf, "Login", "Password", NULL);

      gint to = g_key_file_get_integer(kf, "Cache", "Timeout", &local_err);
      if (local_err == NULL)
        opt_cache_timout = to;
      else
        g_clear_error(&local_err);
    }
    g_free(tmp);
    g_key_file_free(kf);
  }

  if (!opt_username)
  {
    g_printerr("ERROR: You must specify your mega.co.nz username (email)\n");
    exit(1);
  }

  if (!opt_password && opt_no_ask_password)
  {
    g_printerr("ERROR: You must specify your mega.co.nz password\n");
    exit(1);
  }

  if (!opt_password)
    opt_password = input_password();
}

static gboolean is_email_valid(const gchar* email)
{
  // Source: http://stackoverflow.com/questions/201323/using-a-regular-expression-to-validate-an-email-address/1917982#1917982
  const gchar* email_regex =
   "(?(DEFINE)                                                                                           " 
   "  (?<addr_spec>       (?&local_part) \\@ (?&domain))                                                 " 
   "  (?<local_part>      (?&dot_atom) | (?&quoted_string))                                              " 
   "  (?<domain>          (?&dot_atom) | (?&domain_literal))                                             " 
   "  (?<domain_literal>  (?&CFWS)? \\[ (?: (?&FWS)? (?&dcontent))* (?&FWS)? \\] (?&CFWS)?)              " 
   "  (?<dcontent>        (?&dtext) | (?&quoted_pair))                                                   " 
   "  (?<dtext>           (?&NO_WS_CTL) | [\\x21-\\x5a\\x5e-\\x7e])                                      " 
   "  (?<atext>           (?&ALPHA) | (?&DIGIT) | [!#\\$%&'*+-/=?^_`{|}~])                               " 
   "  (?<atom>            (?&CFWS)? (?&atext)+ (?&CFWS)?)                                                " 
   "  (?<dot_atom>        (?&CFWS)? (?&dot_atom_text) (?&CFWS)?)                                         " 
   "  (?<dot_atom_text>   (?&atext)+ (?: \\. (?&atext)+)*)                                               " 
   "  (?<text>            [\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])                                            " 
   "  (?<quoted_pair>     \\\\ (?&text))                                                                 " 
   "  (?<qtext>           (?&NO_WS_CTL) | [\\x21\\x23-\\x5b\\x5d-\\x7e])                                 " 
   "  (?<qcontent>        (?&qtext) | (?&quoted_pair))                                                   " 
   "  (?<quoted_string>   (?&CFWS)? (?&DQUOTE) (?:(?&FWS)? (?&qcontent))* (?&FWS)? (?&DQUOTE) (?&CFWS)?) " 
   "  (?<word>            (?&atom) | (?&quoted_string))                                                  " 
   "  (?<phrase>          (?&word)+)                                                                     " 
   "  (?<FWS>             (?: (?&WSP)* (?&CRLF))? (?&WSP)+)                                              " 
   "  (?<ctext>           (?&NO_WS_CTL) | [\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e])                           " 
   "  (?<ccontent>        (?&ctext) | (?&quoted_pair) | (?&comment))                                     " 
   "  (?<comment>         \\( (?: (?&FWS)? (?&ccontent))* (?&FWS)? \\) )                                 " 
   "  (?<CFWS>            (?: (?&FWS)? (?&comment))* (?: (?:(?&FWS)? (?&comment)) | (?&FWS)))            " 
   "  (?<NO_WS_CTL>       [\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f])                                       " 
   "  (?<ALPHA>           [A-Za-z])                                                                      " 
   "  (?<DIGIT>           [0-9])                                                                         " 
   "  (?<CRLF>            \\x0d \\x0a)                                                                   " 
   "  (?<DQUOTE>          \" )                                                                           " 
   "  (?<WSP>             [\\x20\\x09])                                                                  " 
   ")                                                                                                    " 
   "(?&addr_spec)";

  return g_regex_match_simple(email_regex, email, G_REGEX_EXTENDED | G_REGEX_ANCHORED, 0);
}

static gboolean is_valid_user_handle(const gchar* handle)
{
  return g_regex_match_simple("^[a-zA-Z0-9]{11}$", handle, 0, 0);
}

MegaSession* tool_start_session(void)
{
  GError *local_err = NULL;
  MegaSession* session;
  gboolean needs_login = TRUE;
  gchar* sid = NULL;
  
  session = mega_session_new();
  
  if (tool_debug & DEBUG_API)
    g_object_set(mega_session_get_api(session), "debug", TRUE, NULL);

  // try to load cache

  if (!opt_reload_files)
  {
    if (mega_session_load(session, opt_username, opt_password, &local_err))
    {
      if (opt_cache_timout > 0 && mega_session_is_fresh(session, opt_cache_timout))
        return session;
    }
    else
    {
      if (g_error_matches(local_err, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_WRONG_PASSWORD))
      {
        g_printerr("ERROR: Incorrect password for account '%s'\n", opt_username);
        goto err;
      }

      g_clear_error(&local_err);
    }
  }

  // try to open existing session (load user info from the server)

  sid = g_strdup(mega_api_get_session_id(mega_session_get_api(session)));
  mega_session_close(session);

  if (sid)
  {
    if (mega_session_open(session, opt_password, sid, &local_err))
    {
      needs_login = FALSE;
    }
    else
    {
      if (!g_error_matches(local_err, MEGA_API_ERROR, MEGA_API_ERROR_EACCESS))
      {
        g_printerr("ERROR: Can't get account information: %s\n", local_err ? local_err->message : "unknown error");
        g_free(sid);
        goto err;
      }

      g_clear_error(&local_err);
    }

    g_free(sid);
  }

  if (needs_login)
  {
    if (is_valid_user_handle(opt_username))
    {
      if (!mega_session_login_anon(session, opt_username, opt_password, &local_err))
      {
        if (g_error_matches(local_err, MEGA_API_ERROR, MEGA_API_ERROR_ENOENT))
          g_printerr("ERROR: Incorrect username or password for account '%s'\n", opt_username);
        else
          g_printerr("ERROR: Login failed: %s\n", local_err ? local_err->message : "unknown error");

        goto err;
      }
    }
    else if (is_email_valid(opt_username))
    {
      if (!mega_session_login(session, opt_username, opt_password, &local_err))
      {
        if (g_error_matches(local_err, MEGA_API_ERROR, MEGA_API_ERROR_ENOENT))
          g_printerr("ERROR: Incorrect username or password for account '%s'\n", opt_username);
        else
          g_printerr("ERROR: Login failed: %s\n", local_err ? local_err->message : "unknown error");

        goto err;
      }
    }
    else
    {
      g_printerr("ERROR: Invalid user name (%s), provide either email or anonymous account handle\n", opt_username);
      goto err;
    }
  }

  if (mega_filesystem_load(mega_session_get_filesystem(session), &local_err))
  {
    mega_session_save(session, NULL);
    return session;
  }
  else
  {
    g_printerr("ERROR: Can't read filesystem info from mega.co.nz: %s\n", local_err->message);
    goto err;
  }

err:
  g_object_unref(session);
  g_clear_error(&local_err);
  return NULL;
}

void tool_fini(MegaSession* s)
{
  g_clear_object(&s);
  g_option_context_free(opt_context);
}
