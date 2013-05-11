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

/**
 * MegaSession:
 *
 * Session represents an open access to a single user account on Mega.co.nz.
 *
 * Mega allows ephemeral accounts (temporary accounts not associated with
 * email) and standard accounts (permanent account associated with some email).
 *
 * MegaSession allows to register new accounts, login, open existing sessions,
 * close sessions, or logout. Session information can also be persisted locally
 * via save/load methods.
 *
 * TODO:
 * - Open session for exported folder. 
 * - Load fs nodes, shared keys, build pathmap, path functions
 */

#define CACHE_FORMAT_VERSION 4

#include <string.h>
#include <time.h>
#include "mega-session.h"
#include "mega-api.h"
#include "mega-filesystem.h"
#include "mega-aes-key.h"
#include "mega-rsa-key.h"
#include "utils.h"
#include "private-utils.h"

// u_types:
//   0: not registered (!u.email)
//   1: not sent confirmation email (!u.c)
//   2: not yet set RSA key (!u.privk)
//   3: full account

struct _MegaSessionPrivate
{
  MegaApi* api;
  gboolean is_open;
  gint64 last_refresh;

  MegaAesKey* password_key;
  MegaAesKey* master_key;

  MegaRsaKey* rsa_key;

  gchar* user_email;
  gchar* user_name;
  gchar* user_handle;
  gint user_c; // confirmation sent

  MegaFilesystem* filesystem;
};

// {{{ GObject property and signal enums

enum MegaSessionProp
{
  PROP_0,
  PROP_API,
  PROP_PASSWORD_KEY,
  PROP_MASTER_KEY,
  PROP_RSA_KEY,
  PROP_USER_EMAIL,
  PROP_USER_NAME,
  PROP_USER_HANDLE,
  PROP_IS_OPEN,
  PROP_USER_C,
  PROP_LAST_REFRESH,
  PROP_FILESYSTEM,
  N_PROPERTIES
};

enum MegaSessionSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_session_new:
 *
 * Create new #MegaSession object.
 *
 * Returns: #MegaSession object.
 */
MegaSession* mega_session_new(void)
{
  MegaSession *session = g_object_new(MEGA_TYPE_SESSION, NULL);

  return session;
}

static gboolean load_user_info(MegaSession* session, GError** error)
{
  GError *local_err = NULL;
  MegaSessionPrivate* priv;
  gboolean status = FALSE;
  gchar *k, *privk, *pubk, *user_info;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  // do the call

  user_info = mega_api_call_simple(priv->api, 'o', &local_err, "{a:ug}");
  if (!user_info)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  // free user info

  g_clear_object(&priv->master_key);
  g_clear_object(&priv->rsa_key);
  g_clear_pointer(&priv->user_handle, g_free);
  g_clear_pointer(&priv->user_email, g_free);
  g_clear_pointer(&priv->user_name, g_free);

  // basic user info

  priv->user_handle = s_json_get_member_string(user_info, "u");
  priv->user_email = s_json_get_member_string(user_info, "email");
  priv->user_name = s_json_get_member_string(user_info, "name");
  priv->user_c = s_json_get_member_int(user_info, "c", -1);

  // keys

  k = s_json_get_member_string(user_info, "k");
  privk = s_json_get_member_string(user_info, "privk");
  pubk = s_json_get_member_string(user_info, "pubk");

  if (!k)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Missing master key");
    goto out;
  }

  priv->master_key = mega_aes_key_new_from_enc_ubase64(k, priv->password_key);
  if (!mega_aes_key_is_loaded(priv->master_key))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decrypt master key");
    g_clear_object(&priv->master_key);
    goto out;
  }

  if (pubk && privk)
  {
    priv->rsa_key = mega_rsa_key_new();

    if (!mega_rsa_key_load_pubk(priv->rsa_key, pubk))
    {
      g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't load public RSA key");
      g_clear_object(&priv->rsa_key);
      goto out;
    }

    if (!mega_rsa_key_load_enc_privk(priv->rsa_key, privk, priv->master_key))
    {
      g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't load private RSA key");
      g_clear_object(&priv->rsa_key);
      goto out;
    }
  }

  priv->last_refresh = time(NULL);

  status = TRUE;

out:
  g_free(user_info);
  g_free(privk);
  g_free(pubk);
  g_free(k);
  return status;
}

/**
 * mega_session_open:
 * @session: a #MegaSession
 * @password: Password
 * @session_id: Session ID
 * @error:
 *
 * Open existing remote session on the server using session ID.
 *
 * Returns: TRUE on success.
 */
gboolean mega_session_open(MegaSession* session, const gchar* password, const gchar* session_id, GError** error)
{
  GError *local_err = NULL;
  MegaSessionPrivate* priv;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(session_id != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  if (priv->is_open)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Session is already open");
    return FALSE;
  }

  mega_api_set_session_id(priv->api, session_id);

  g_clear_object(&priv->password_key);
  priv->password_key = mega_aes_key_new_from_password(password);

  if (!load_user_info(session, &local_err))
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  priv->is_open = TRUE;

  return TRUE;
}

/**
 * mega_session_login:
 * @session: a #MegaSession
 * @username: 
 * @password: 
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_login(MegaSession* session, const gchar* username, const gchar* password, GError** error)
{
  GError *local_err = NULL;
  MegaSessionPrivate* priv;
  MegaAesKey *pkey = NULL, *mkey = NULL;
  MegaRsaKey* rsa_key = NULL;
  gchar *login_info, *k = NULL, *privk = NULL, *csid = NULL;
  gboolean status = FALSE;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(username != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  if (priv->is_open)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Session is already open");
    return FALSE;
  }

  pkey = mega_aes_key_new_from_password(password);

  // do the call

  login_info = mega_api_call_simple(priv->api, 'o', &local_err, "{a:us, uh:%S, user:%S}", mega_aes_key_make_username_hash(pkey, username), g_ascii_strdown(username, -1));
  if (!login_info)
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  k = s_json_get_member_string(login_info, "k");
  privk = s_json_get_member_string(login_info, "privk");
  csid = s_json_get_member_string(login_info, "csid");

  mkey = mega_aes_key_new_from_enc_ubase64(k, pkey);
  if (!mega_aes_key_is_loaded(mkey))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decrypt master key");
    goto out;
  }

  rsa_key = mega_rsa_key_new();
  if (!mega_rsa_key_load_enc_privk(rsa_key, privk, mkey))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't load private RSA key");
    goto out;
  }

  gchar* sid = mega_rsa_key_decrypt_sid(rsa_key, csid);
  if (!sid)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decrypt session ID");
    goto out;
  }

  g_clear_object(&priv->password_key);
  priv->password_key = g_object_ref(pkey);

  mega_api_set_session_id(priv->api, sid);

  status = TRUE;
out:
  g_free(k);
  g_free(privk);
  g_free(csid);
  g_free(login_info);
  g_clear_object(&mkey);
  g_clear_object(&pkey);
  g_clear_object(&rsa_key);

  if (status) 
    status = load_user_info(session, error);

  priv->is_open = status;

  return status;
}

/**
 * mega_session_login_anon:
 * @session: a #MegaSession
 * @user_handle: Ephemeral account user handle.
 * @password: Ephemeral account password.
 * @error: 
 *
 * Logint to an ephemeral account.
 *
 * Returns: TRUE on success.
 */
gboolean mega_session_login_anon(MegaSession* session, const gchar* user_handle, const gchar* password, GError** error)
{
  GError* local_err = NULL;
  MegaSessionPrivate* priv;
  MegaAesKey *mkey = NULL, *pkey = NULL;
  gchar *us_data, *k = NULL, *tsid = NULL;
  guchar* ssc = NULL;
  guchar ssc_enc[16];
  gsize ssc_len;
  gboolean status = FALSE;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(user_handle != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  if (priv->is_open)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Session is already open");
    return FALSE;
  }

  us_data = mega_api_call_simple(priv->api, 'o', &local_err, "{a:us, user:%s}", user_handle);
  if (!us_data)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  k = s_json_get_member_string(us_data, "k");
  tsid = s_json_get_member_string(us_data, "tsid");
  g_free(us_data);

  pkey = mega_aes_key_new_from_password(password);
  mkey = mega_aes_key_new_from_enc_ubase64(k, pkey);
  if (!mega_aes_key_is_loaded(mkey))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decrypt master key");
    goto out;
  }

  ssc = mega_base64urldecode(tsid, &ssc_len);
  if (!ssc || ssc_len < 32)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decode tsid");
    goto out;
  }

  mega_aes_key_encrypt_raw(mkey, ssc, ssc_enc, 16);
  if (memcmp(ssc_enc, ssc + ssc_len - 16, 16))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_WRONG_PASSWORD, "SSC failed");
    goto out;
  }

  g_clear_object(&priv->master_key);
  priv->master_key = g_object_ref(mkey);

  g_clear_object(&priv->password_key);
  priv->password_key = g_object_ref(pkey);

  g_clear_pointer(&priv->user_handle, g_free);
  priv->user_handle = g_strdup(user_handle);

  mega_api_set_session_id(priv->api, tsid);

  priv->last_refresh = time(NULL);
  priv->is_open = TRUE;

  status = TRUE;
out:
  g_free(ssc);
  g_free(k);
  g_free(tsid);
  g_clear_object(&pkey);
  g_clear_object(&mkey);
  return status;
}

/**
 * mega_session_logout:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_logout(MegaSession* session, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Logout is not implemented");
  return FALSE;
}

/**
 * mega_session_close:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns:
 */
gboolean mega_session_close(MegaSession* session)
{
  MegaSessionPrivate* priv;

  g_return_if_fail(MEGA_IS_SESSION(session));

  priv = session->priv;

  priv->is_open = FALSE;
  mega_api_set_session_id(priv->api, NULL);

  g_clear_object(&priv->password_key);
  g_clear_object(&priv->master_key);
  g_clear_object(&priv->rsa_key);

  g_clear_pointer(&priv->user_email, g_free);
  g_clear_pointer(&priv->user_name, g_free);
  g_clear_pointer(&priv->user_handle, g_free);

  priv->user_c = 0;
  priv->last_refresh = 0;

  mega_filesystem_clear(priv->filesystem);

  return TRUE;
}

// calculate cache file path
static gchar* get_cache_path(const gchar* user_handle)
{
  g_return_val_if_fail(user_handle != NULL, NULL);

  GChecksum* cs = g_checksum_new(G_CHECKSUM_SHA1);
  g_checksum_update(cs, user_handle, -1);
  gchar* filename = g_strconcat(g_checksum_get_string(cs), ".megatools.cache", NULL);
  gchar* path = g_build_filename(g_get_tmp_dir(), filename, NULL);
  g_free(filename);
  g_checksum_free(cs);

  return path;
}

/**
 * mega_session_save:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_save(MegaSession* session, GError** error)
{
  GError *local_err = NULL;
  MegaSessionPrivate* priv;
  gchar* path;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  if (!priv->is_open)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Session is not open");
    return FALSE;
  }

  if (priv->user_email)
    path = get_cache_path(priv->user_email);
  else
    path = get_cache_path(priv->user_handle);

  gchar* cache_data = mega_session_get_json(session);
  //g_print("%s\n", s_json_pretty(cache_data));

  gchar* tmp = g_strconcat("MEGA", cache_data, NULL);
  gchar* cipher = mega_aes_key_encrypt_string_cbc(priv->password_key, tmp);
  g_free(tmp);
  g_free(cache_data);

  if (!g_file_set_contents(path, cipher, -1, &local_err))
  {
    g_propagate_error(error, local_err);
    g_free(cipher);
    g_free(path);
    return FALSE;
  }

  g_free(cipher);
  g_free(path);
  return TRUE;
}

/**
 * mega_session_load:
 * @session: a #MegaSession
 * @username: 
 * @password: 
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_load(MegaSession* session, const gchar* username, const gchar* password, GError** error)
{
  GError* local_err = NULL;
  gchar* cipher = NULL;
  gchar* path;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(username != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  path = get_cache_path(username);

  // load cipher data
  if (!g_file_get_contents(path, &cipher, NULL, &local_err))
  {
    if (g_error_matches(local_err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
    {
      g_clear_error(&local_err);
      g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_NO_CACHE, "Missing cache file");
    }
    else
      g_propagate_error(error, local_err);

    g_free(path);
    return FALSE;
  }

  g_free(path);

  // calculate password key
  MegaAesKey* password_key = mega_aes_key_new_from_password(password);
  GBytes* data_bytes = mega_aes_key_decrypt_cbc(password_key, cipher);
  const guchar* data = g_bytes_get_data(data_bytes, NULL);
  g_object_unref(password_key);
  g_free(cipher);

  if (!data_bytes || g_bytes_get_size(data_bytes) < 4)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Corrupted cache file");
    g_bytes_unref(data_bytes);
    return FALSE;
  }

  if (memcmp(data, "MEGA", 4) != 0)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_WRONG_PASSWORD, "Incorrect password");
    g_bytes_unref(data_bytes);
    return FALSE;
  }

  if (!s_json_is_valid(data + 4))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Corrupted cache file");
    g_bytes_unref(data_bytes);
    return FALSE;
  }

  gchar* cache_obj = s_json_get(data + 4);
  g_bytes_unref(data_bytes);

  if (!mega_session_set_json(session, cache_obj))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Corrupt cache");
    g_free(cache_obj);
    return FALSE;
  }

  g_free(cache_obj);
  return TRUE;
}

/**
 * mega_session_get_info:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gchar* mega_session_get_info(MegaSession* session, GError** error)
{
  GError *local_err = NULL;
  MegaSessionPrivate* priv;

  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  priv = session->priv;

  // return all kinds of info encoded in a JSON string

  gchar* request = s_json_build("[{a:uq, strg:1, xfer:1, pro:1}, {a:uavl}, {a:utt}, {a:utp}, {a:usl}, {a:ug}]");
  gchar* response = mega_api_call(priv->api, request, &local_err);
  g_free(request);

  if (!response)
  {
    g_propagate_error(error, local_err);
    return NULL;
  }
  
  if (s_json_get_type(response) != S_JSON_TYPE_ARRAY || s_json_get_type(s_json_get_element(response, 0)) != S_JSON_TYPE_OBJECT)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Unrecognized response from the server");
    g_free(response);
    return FALSE;
  }

  const gchar* uq = s_json_get_element(response, 0);   // account quota
  const gchar* uavl = s_json_get_element(response, 1); // vouchers     
  const gchar* utt = s_json_get_element(response, 2);  // transactions 
  const gchar* utp = s_json_get_element(response, 3);  // purchases    
  const gchar* usl = s_json_get_element(response, 4);  // sessions     
  const gchar* ug = s_json_get_element(response, 5);   // user

  SJsonGen *gen = s_json_gen_new();
  s_json_gen_start_object(gen);
  s_json_gen_member_build(gen, "user", "%S", s_json_get_member_string(ug, "u"));
  s_json_gen_member_build(gen, "email", "%S", s_json_get_member_string(ug, "email"));
  s_json_gen_member_build(gen, "name", "%S", s_json_get_member_string(ug, "name"));
  s_json_gen_member_build(gen, "master_key", "%S", s_json_get_member_string(ug, "k"));
  s_json_gen_member_build(gen, "public_key", "%S", s_json_get_member_string(ug, "pubk"));
  s_json_gen_member_build(gen, "secret_key", "%S", s_json_get_member_string(ug, "privk"));
  s_json_gen_member_build(gen, "trust_session", "%S", s_json_get_member_string(ug, "ts")); // verify by comparing first 16b with last 16b decrypted by mk
  s_json_gen_member_build(gen, "total_storage", "%i", s_json_get_member_int(uq, "mstrg", -1));
  s_json_gen_member_build(gen, "used_storage", "%i", s_json_get_member_int(uq, "cstrg", -1));
  s_json_gen_member_build(gen, "balance", "%j", s_json_path(uq, ".balance[0][0]!n"));

  gint utype = s_json_get_member_int(uq, "utype", 0);
  if (utype == 0)
    s_json_gen_member_string(gen, "user_type", "Free");
  else if (utype == 1)
    s_json_gen_member_string(gen, "user_type", "Pro I");
  else if (utype == 2)
    s_json_gen_member_string(gen, "user_type", "Pro II");
  else if (utype == 3)
    s_json_gen_member_string(gen, "user_type", "Pro III");
  else
    s_json_gen_member_string(gen, "user_type", "Unknown");

  if (utype > 0)
  {
    const gchar* stype = s_json_path(uq, ".stype!s");  // SO
    const gchar* scycle = s_json_path(uq, ".scycle!s"); // S = WMY snext, O = suntil
    const gchar* snext = s_json_path(uq, ".snext!i");
    const gchar* suntil = s_json_path(uq, ".suntil!i");

    if (stype)
    {
      gchar* st = s_json_get_string(stype);

      if (!strcmp(st, "S"))
      {
        s_json_gen_member_string(gen, "subscription_type", "Subscription");
        if (scycle && snext)
        {
          gchar* cycle = s_json_get_string(scycle);
          gint64 next = s_json_get_int(snext, 0);
          GDateTime* dt = g_date_time_new_from_unix_local(next);

          if (!strcmp(cycle, "W"))
            s_json_gen_member_string(gen, "subscription_cycle", "Weekly");
          else if (!strcmp(cycle, "M"))
            s_json_gen_member_string(gen, "subscription_cycle", "Monthly");
          else if (!strcmp(cycle, "Y"))
            s_json_gen_member_string(gen, "subscription_cycle", "Yearly");

          if (next)
            s_json_gen_member_build(gen, "subscription_next_payment", "%S", g_date_time_format(dt, "%F"));

          g_date_time_unref(dt);
          g_free(cycle);
        }

      }
      else if (!strcmp(st, "O"))
      {
        s_json_gen_member_string(gen, "subscription_type", "One-time");
        if (suntil)
        {
          gint64 until = s_json_get_int(suntil, 0);
          GDateTime* dt = g_date_time_new_from_unix_local(until);

          if (until)
            s_json_gen_member_build(gen, "subscription_until", "%S", g_date_time_format(dt, "%F"));

          g_date_time_unref(dt);
        }
      }

      g_free(st);
    }
  }

  // sessions

  s_json_gen_member_array(gen, "sessions");

  gsize i, l;
  gchar** sessions = s_json_get_elements(usl);
  for (l = g_strv_length(sessions), i = l > 10 ? l - 10 : 0; i < l; i++)
  {
    const gchar* s = sessions[i];

    s_json_gen_build(gen, "{"
      "date: %j,"
      "useragent: %j,"
      "ip: %j,"
      "country: %j,"
      "current: %j"
    "}", 
      s_json_path(s, "[1]!i"), 
      s_json_path(s, "[2]!s"), 
      s_json_path(s, "[3]!s"), 
      s_json_path(s, "[4]!s"), 
      s_json_path(s, "[5]!i")
    );
  }

  s_json_gen_end_array(gen);    

  // finish info object

  s_json_gen_end_object(gen);
  g_free(response);
  return s_json_gen_done(gen);

#if 0
   BWMAN
     var bwman = true;
     if (typeof json[0].srvratio == 'undefined') bwman = false;
bw: Math.round(json[0].mxfer/1024/1024/1024),
servbw_used: Math.round(json[0].csxfer/1024/1024/1024),
downbw_used: Math.round(json[0].caxfer/1024/1024/1024),	
bwman: bwman,
servbw_limit: json[0].srvratio,

  var servbwperc = Math.round(u.servbw_used / u.bw * 100);  // bandwidth for serving exported files
  var downbwperc = Math.round(u.downbw_used / u.bw * 100);  // bandwidth for downloading exprote files
  var stperc = Math.round(u.space_used / u.space * 100);    // space used
#endif
}

/**
 * mega_session_register_anon:
 * @session: a #MegaSession
 * @password: Ephemeral account password.
 * @error: 
 *
 * Register new ephemeral account, and return its user handle.
 *
 * Returns: User handle.
 */
gchar* mega_session_register_anon(MegaSession* session, const gchar* password, GError** error)
{
  GError* local_err = NULL;
  MegaSessionPrivate* priv;
  MegaAesKey *mkey, *pkey;
  gchar* up_data;
  gchar* user_handle = NULL;
  guchar ssc[32];

  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);
  g_return_val_if_fail(password != NULL, NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  priv = session->priv;

  if (priv->is_open)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Session is already open");
    return NULL;
  }

  pkey = mega_aes_key_new_from_password(password);
  mkey = mega_aes_key_new_generated();

  // setup create ssc
  mega_randomness(ssc, 16);
  mega_aes_key_encrypt_raw(mkey, ssc, ssc + 16, 16);

  up_data = mega_api_call_simple(priv->api, 's', &local_err, "{a:up, k:%S, ts:%S}", mega_aes_key_get_enc_ubase64(mkey, pkey), mega_base64urlencode(ssc, 32));
  if (!up_data)
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  user_handle = s_json_get_string(up_data);
  g_free(up_data);

out:
  g_clear_object(&mkey);
  g_clear_object(&pkey);
  return user_handle;
}

/**
 * mega_session_register:
 * @session: a #MegaSession
 * @email: Email (username).
 * @password: Password.
 * @name: Real name.
 * @error: 
 *
 * Register new account.
 *
 * Returns: Registration state for use in mega_session_register_verify.
 */
gchar* mega_session_register(MegaSession* session, const gchar* email, const gchar* password, const gchar* name, GError** error)
{
  GError* local_err = NULL;
  MegaSessionPrivate* priv;
  gchar* status = NULL;
  gchar* user_handle;
  gchar* node;

  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);
  g_return_val_if_fail(email != NULL, NULL);
  g_return_val_if_fail(password != NULL, NULL);
  g_return_val_if_fail(name != NULL, NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  priv = session->priv;

  // register anon account

  user_handle = mega_session_register_anon(session, password, &local_err);
  if (!user_handle)
  {
    g_propagate_error(error, local_err);
    return NULL;
  }

  // login to anon account

  if (!mega_session_login_anon(session, user_handle, password, &local_err))
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  // set user name - {"a":"up","name":"Bob Brown"} -> "-a1DHeWfguY"

  node = mega_api_call_simple(priv->api, 's', &local_err, "{a:up, name:%s}", name);
  if (!node)
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  g_free(node);

  // request signup link - [{"a":"uc","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ic","n":"Qm9iIEJyb3du","m":"bWVnb3VzQGVtYWlsLmN6"}] -> [0]

  // c_data = aes(master_key, pw_key) + aes(verify, pw_key)
  guchar* master_key_data = mega_aes_key_get_binary(priv->master_key);
  guchar c_data[32] = {0};
  memcpy(c_data, master_key_data, 16);
  mega_randomness(c_data + 16, 4);
  mega_randomness(c_data + 16 + 12, 4);
  g_free(master_key_data);

  // this will set new k from the first 16 bytes of c
  node = mega_api_call_simple(priv->api, 'i', &local_err, "{a:uc, c:%S, n:%S, m:%S}", mega_aes_key_encrypt(priv->password_key, c_data, sizeof(c_data)), mega_base64urlencode(name, strlen(name)), mega_base64urlencode(email, strlen(email)));
  if (!node)
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  g_free(node);

  // generate state string

  gchar* state_json = s_json_build("{p:%s,c:%S,u:%s}", password, mega_base64urlencode(c_data + 16, 16), user_handle);
  status = mega_base64urlencode(state_json, strlen(state_json));
  g_free(state_json);

out:
  g_free(user_handle);
  mega_session_close(session);
  return status;
}

/**
 * mega_session_register_verify:
 * @session: a #MegaSession
 * @state: Registration state.
 * @signup_key: Signup key.
 * @error: 
 *
 * Finish registration.
 *
 * Returns: TRUE on success.
 */
gboolean mega_session_register_verify(MegaSession* session, const gchar* state, const gchar* signup_key, GError** error)
{
  MegaSessionPrivate* priv;
  GError* local_err = NULL;
  gboolean status = FALSE;
  gchar* state_data = NULL;
  gsize len;
  gchar* user_handle = NULL;
  MegaRsaKey* rsa_key = NULL;
  MegaAesKey* mkey = NULL;
  gchar *b64_email = NULL, *b64_master_key = NULL, *b64_challenge = NULL, *email = NULL, *password = NULL;
  GBytes* challenge = NULL;
  guchar* state_challenge = NULL;
  gchar* node;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(state != NULL, FALSE);
  g_return_val_if_fail(signup_key != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = session->priv;

  // decode state

  state_data = mega_base64urldecode(state, &len);
  if (!state_data || !s_json_is_valid(state_data))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Invalid registration state string");
    goto out;
  }

  user_handle = s_json_get_member_string(state_data, "u");
  password = s_json_get_member_string(state_data, "p");
  gchar* c = s_json_get_member_string(state_data, "c");
  state_challenge = mega_base64urldecode(c, &len);
  g_free(c);

  if (!user_handle || !state_challenge || !password || len != 16)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Invalid registration state string");
    goto out;
  }

  // login to anon account

  if (!mega_session_login_anon(session, user_handle, password, &local_err))
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  // generate RSA key first, to handle failure early

  rsa_key = mega_rsa_key_new();
  if (!mega_rsa_key_generate(rsa_key))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't generate RSA key");
    goto out;
  }

  // send confirmation
  //
  // https://mega.co.nz/#confirmZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg
  //
  // [{"a":"ud","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg"}] 
  //
  // -> [["bWVnb3VzQGVtYWlsLmN6","Qm9iIEJyb3du","-a1DHeWfguY","ZOB7VJrNXFvCzyZBIcdWhg","vmXh0lq2takSMSkCYfXuJw"]]
  //            ^                       ^            ^                    ^                       ^
  //          email                    name        handle       enc(master_key, pwkey)   enc(challenge, pwkey)

  node = mega_api_call_simple(priv->api, 'a', &local_err, "{a:ud, c:%s}", signup_key);
  if (!node)
  {
    g_propagate_error(error, local_err);
    goto out;
  }

  gchar** arr = s_json_get_elements(node);
  if (g_strv_length(arr) != 5)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Wrong number of elements in retval from 'ud' (%d)", g_strv_length(arr));
    g_free(arr);
    g_free(node);
    goto out;
  }

  b64_email = s_json_get_string(arr[0]);
  b64_master_key = s_json_get_string(arr[3]);
  b64_challenge = s_json_get_string(arr[4]);

  g_free(arr);
  g_free(node);

  if (b64_email == NULL || b64_master_key == NULL || b64_challenge == NULL)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Invalid data returned by 'ud'");
    goto out;
  }

  mkey = mega_aes_key_new_from_enc_ubase64(b64_master_key, priv->password_key);
  if (!mega_aes_key_is_loaded(mkey))
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decrypt master key from 'ud' output");
    goto out;
  }

  email = mega_base64urldecode(b64_email, &len);
  challenge = mega_aes_key_decrypt(priv->password_key, b64_challenge);
  if (email == NULL || challenge == NULL)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Can't decode challenge and email from 'ud' output");
    goto out;
  }

  // check challenge response

  if (g_bytes_get_size(challenge) != 16 || memcmp(g_bytes_get_data(challenge, NULL), state_challenge, 16) != 0)
  {
    g_set_error(error, MEGA_SESSION_ERROR, MEGA_SESSION_ERROR_OTHER, "Invalid challenge response");
    goto out;
  }

  // save uh and c (send signup key)
  // [{"uh":"VcWbhpU9cb0","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg","a":"up"}] -> ["-a1DHeWfguY"]

  node = mega_api_call_simple(priv->api, 's', &local_err, "{a:up, c:%s, uh:%S, pubk:%S, privk:%S}", signup_key, mega_aes_key_make_username_hash(priv->password_key, email), mega_rsa_key_get_pubk(rsa_key), mega_rsa_key_get_enc_privk(rsa_key, mkey));
  if (!node)
  {
    g_propagate_error(error, local_err);
    goto out; 
  }

  g_free(node);
  status = TRUE;

out:
  g_free(email);
  g_bytes_unref(challenge);
  g_clear_object(&rsa_key);
  g_clear_object(&mkey);
  g_free(b64_email);
  g_free(b64_master_key);
  g_free(b64_challenge);
  g_free(state_challenge);
  g_free(password);
  g_free(user_handle);
  g_free(state_data);
  return status;
}

#if 0
gboolean mega_session_open_exp_folder(mega_session* s, const gchar* n, const gchar* key, GError** error)
{
  GError* local_err = NULL;
  gsize len, i, l;
  GSList* list = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(n != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  mega_session_close(s);

  s->master_key = mega_aes_key_new_from_ubase64(key);
  if (!mega_aes_key_is_loaded(s->master_key))
  {
    g_object_unref(s->master_key);
    s->master_key = NULL;
    return FALSE;
  }

  s->sid_param_name = "n";
  s->sid = g_strdup(n);

  // login user
  gchar* f_node = mega_api_call_simple(priv->api, 'o', NULL, &local_err, "[{a:f, c:1, r:1}]");
  if (!f_node)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  const gchar* ff_node = s_json_get_member(f_node, "f");
  if (ff_node && s_json_get_type(ff_node) == S_JSON_TYPE_ARRAY)
  {
    const gchar* node;
    gint i = 0;

    while ((node = s_json_get_element(ff_node, i++)))
    {
      if (s_json_get_type(node) == S_JSON_TYPE_OBJECT)
      {
        // first node is the root folder
        if (i == 1)
        {
          gchar* node_h = s_json_get_member_string(node, "h");
          add_share_key(s, node_h, s->master_key);
          g_free(node_h);
        }

        // import nodes into the fs
        mega_node* n = mega_node_parse(s, node);
        if (n)
        {
          if (i == 1)
          {
            g_free(n->parent_handle);
            n->parent_handle = NULL;
          }

          list = g_slist_prepend(list, n);
        }
      }
    }
  }

  s->fs_nodes = g_slist_reverse(list);
  update_pathmap(s);

  g_free(f_node);
  return TRUE;
}
#endif

/**
 * mega_session_get_api:
 * @session: a #MegaSession
 *
 * Get API object used by the session.
 *
 * Returns: (transfer none): Api object.
 */
MegaApi* mega_session_get_api(MegaSession* session)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  return session->priv->api;
}

/**
 * mega_session_get_master_key:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns: (transfer none):
 */
MegaAesKey* mega_session_get_master_key(MegaSession* session)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  return session->priv->master_key;
}

/**
 * mega_session_get_rsa_key:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns: (transfer none):
 */
MegaRsaKey* mega_session_get_rsa_key(MegaSession* session)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  return session->priv->rsa_key;
}

/**
 * mega_session_get_filesystem:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns: (transfer none):
 */
MegaFilesystem* mega_session_get_filesystem(MegaSession* session)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  return session->priv->filesystem;
}

/**
 * mega_session_get_user_handle:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns: 
 */
const gchar* mega_session_get_user_handle(MegaSession* session)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  return session->priv->user_handle;
}

/**
 * mega_session_get_json:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns: 
 */
gchar* mega_session_get_json(MegaSession* session)
{
  MegaSessionPrivate* priv;
  SJsonGen *gen;

  g_return_val_if_fail(MEGA_IS_SESSION(session), NULL);

  priv = session->priv;

  gen = s_json_gen_new();
  s_json_gen_start_object(gen);

  // serialize session object
  s_json_gen_member_int(gen, "version", CACHE_FORMAT_VERSION);
  s_json_gen_member_int(gen, "last_refresh", priv->last_refresh);

  s_json_gen_member_string(gen, "sid", mega_api_get_session_id(priv->api));
  s_json_gen_member_build(gen, "password_key", "%S", mega_aes_key_get_ubase64(priv->password_key));
  s_json_gen_member_build(gen, "master_key", "%S", mega_aes_key_get_ubase64(priv->master_key));
  if (priv->rsa_key)
  {
    s_json_gen_member_build(gen, "rsa_privk", "%S", mega_rsa_key_get_enc_privk(priv->rsa_key, priv->master_key));
    s_json_gen_member_build(gen, "rsa_pubk", "%S", mega_rsa_key_get_pubk(priv->rsa_key));
  }
  s_json_gen_member_string(gen, "user_handle", priv->user_handle);
  s_json_gen_member_string(gen, "user_name", priv->user_name);
  s_json_gen_member_string(gen, "user_email", priv->user_email);
  s_json_gen_member_int(gen, "user_c", priv->user_c);
  s_json_gen_member_build(gen, "filesystem", "%J", mega_filesystem_get_json(priv->filesystem));

  s_json_gen_end_object(gen);
  return s_json_gen_done(gen);
}

/**
 * mega_session_set_json:
 * @session: a #MegaSession
 * @json: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_set_json(MegaSession* session, const gchar* json)
{
  MegaSessionPrivate* priv;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(json != NULL, FALSE);

  priv = session->priv;

  if (s_json_get_type(json) != S_JSON_TYPE_OBJECT)
    return FALSE;

  if (s_json_get_member_int(json, "version", 0) != CACHE_FORMAT_VERSION)
    return FALSE;

  gchar* sid = s_json_get_member_string(json, "sid");
  mega_api_set_session_id(priv->api, sid);
  g_free(sid);

  priv->is_open = TRUE;
  priv->last_refresh = s_json_get_member_int(json, "last_refresh", 0);

  g_clear_object(&priv->password_key);
  priv->password_key = s_json_get_member_aes_key(json, "password_key");

  g_clear_object(&priv->master_key);
  priv->master_key = s_json_get_member_aes_key(json, "master_key");

  if (priv->master_key)
  {
    gchar* pubk = s_json_get_member_string(json, "rsa_pubk");
    gchar* privk = s_json_get_member_string(json, "rsa_privk");

    if (pubk && privk)
    {
      g_clear_object(&priv->rsa_key);
      priv->rsa_key = mega_rsa_key_new();

      if (!mega_rsa_key_load_enc_privk(priv->rsa_key, privk, priv->master_key) || !mega_rsa_key_load_pubk(priv->rsa_key, pubk)) 
        return FALSE;
    }

    g_free(pubk);
    g_free(privk);
  }

  priv->user_handle = s_json_get_member_string(json, "user_handle");
  priv->user_name = s_json_get_member_string(json, "user_name");
  priv->user_email = s_json_get_member_string(json, "user_email");
  priv->user_c = s_json_get_member_int(json, "user_c", 0);

  if (!mega_filesystem_set_json(priv->filesystem, s_json_path(json, ".filesystem")))
    return FALSE;

  return TRUE;
}

/**
 * mega_session_is_fresh:
 * @session: a #MegaSession
 * @max_age: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_is_fresh(MegaSession* session, gint64 max_age)
{
  MegaSessionPrivate* priv;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(max_age >= 0, FALSE);

  priv = session->priv;

  return priv->last_refresh > 0 && (priv->last_refresh + max_age) >= time(NULL) && mega_filesystem_is_fresh(priv->filesystem, max_age);
}

// {{{ GObject type setup

static void mega_session_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_session_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  switch (property_id)
  {
    case PROP_API:
      g_value_set_object(value, priv->api);
      break;

    case PROP_PASSWORD_KEY:
      g_value_set_object(value, priv->password_key);
      break;

    case PROP_MASTER_KEY:
      g_value_set_object(value, priv->master_key);
      break;

    case PROP_RSA_KEY:
      g_value_set_object(value, priv->rsa_key);
      break;

    case PROP_USER_EMAIL:
      g_value_set_string(value, priv->user_email);
      break;

    case PROP_USER_NAME:
      g_value_set_string(value, priv->user_name);
      break;

    case PROP_USER_HANDLE:
      g_value_set_string(value, priv->user_handle);
      break;

    case PROP_IS_OPEN:
      g_value_set_boolean(value, priv->is_open);
      break;

    case PROP_USER_C:
      g_value_set_int(value, priv->user_c);
      break;

    case PROP_LAST_REFRESH:
      g_value_set_int64(value, priv->last_refresh);
      break;

    case PROP_FILESYSTEM:
      g_value_set_object(value, priv->filesystem);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaSession, mega_session, G_TYPE_OBJECT);

static void mega_session_init(MegaSession *session)
{
  session->priv = G_TYPE_INSTANCE_GET_PRIVATE(session, MEGA_TYPE_SESSION, MegaSessionPrivate);

  session->priv->api = mega_api_new();
  //g_object_set(session->priv->api, "debug", TRUE, NULL);

  session->priv->filesystem = mega_filesystem_new(session);
}

static void mega_session_dispose(GObject *object)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  g_clear_object(&priv->filesystem);

  G_OBJECT_CLASS(mega_session_parent_class)->dispose(object);
}

static void mega_session_finalize(GObject *object)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  mega_session_close(session);

  g_clear_object(&priv->api);

  G_OBJECT_CLASS(mega_session_parent_class)->finalize(object);
}

static void mega_session_class_init(MegaSessionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_session_set_property;
  gobject_class->get_property = mega_session_get_property;
  gobject_class->dispose = mega_session_dispose;
  gobject_class->finalize = mega_session_finalize;

  g_type_class_add_private(klass, sizeof(MegaSessionPrivate));

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "api",
    /* nick    */ "Api",
    /* blurb   */ "Set/get api",
    /* is_type */ MEGA_TYPE_API,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_API, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "password-key",
    /* nick    */ "Password-key",
    /* blurb   */ "Get password AES key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_PASSWORD_KEY, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "master-key",
    /* nick    */ "Master-key",
    /* blurb   */ "Get master AES key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_MASTER_KEY, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "rsa-key",
    /* nick    */ "Rsa-key",
    /* blurb   */ "Get RSA key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_RSA_KEY, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-email",
    /* nick    */ "User-email",
    /* blurb   */ "Get user email",
    /* default */ NULL,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_USER_EMAIL, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-name",
    /* nick    */ "User-name",
    /* blurb   */ "Get user name",
    /* default */ NULL,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_USER_NAME, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-handle",
    /* nick    */ "User-handle",
    /* blurb   */ "Get user handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE
  );

  g_object_class_install_property(gobject_class, PROP_USER_HANDLE, param_spec);

  param_spec = g_param_spec_boolean(
    /* name    */ "is-open",
    /* nick    */ "Is-open",
    /* blurb   */ "Get session open status",
    /* default */ FALSE,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_IS_OPEN, param_spec);

  param_spec = g_param_spec_int(
    /* name    */ "user-c",
    /* nick    */ "User-c",
    /* blurb   */ "Get user c",
    /* minimum */ 0,
    /* maximum */ 2,
    /* default */ 0,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_USER_C, param_spec);

  param_spec = g_param_spec_int64(
    /* name    */ "last-refresh",
    /* nick    */ "Last-refresh",
    /* blurb   */ "Get last refresh time",
    /* minimum */ 0,
    /* maximum */ G_MAXINT64,
    /* default */ 0,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_LAST_REFRESH, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "filesystem",
    /* nick    */ "Filesystem",
    /* blurb   */ "Get filesystem",
    /* is_type */ MEGA_TYPE_FILESYSTEM,
    /* flags   */ G_PARAM_READABLE
  );

  g_object_class_install_property(gobject_class, PROP_FILESYSTEM, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

GQuark mega_session_error_quark(void)
{
  return g_quark_from_static_string("mega-session-error-quark");
}

// }}}
