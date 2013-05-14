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

#ifndef __MEGA_SESSION_H__
#define __MEGA_SESSION_H__

#include <mega/megatypes.h>
#include <mega/mega-rsa-key.h>

#define MEGA_TYPE_SESSION            (mega_session_get_type())
#define MEGA_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_SESSION, MegaSession))
#define MEGA_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_SESSION, MegaSessionClass))
#define MEGA_IS_SESSION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_SESSION))
#define MEGA_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_SESSION))
#define MEGA_SESSION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_SESSION, MegaSessionClass))

typedef struct _MegaSessionClass MegaSessionClass;
typedef struct _MegaSessionPrivate MegaSessionPrivate;

#define MEGA_SESSION_ERROR mega_session_error_quark()

/**
 * MegaSessionError:
 * @MEGA_SESSION_ERROR_NO_CACHE: Cache does not exist yet.
 * @MEGA_SESSION_ERROR_WRONG_PASSWORD: Invalid password.
 * @MEGA_SESSION_ERROR_OTHER: Other error.
 */

typedef enum 
{
  MEGA_SESSION_ERROR_NO_CACHE,
  MEGA_SESSION_ERROR_WRONG_PASSWORD,
  MEGA_SESSION_ERROR_OTHER
} MegaSessionError;

struct _MegaSession
{
  GObject parent;
  MegaSessionPrivate* priv;
};

struct _MegaSessionClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_session_get_type           (void) G_GNUC_CONST;
GQuark                  mega_session_error_quark        (void);

MegaSession*            mega_session_new                (void);

gboolean                mega_session_login              (MegaSession* session, const gchar* username, const gchar* password, GError** error);
gboolean                mega_session_login_anon         (MegaSession* session, const gchar* user_handle, const gchar* password, GError** error);
gboolean                mega_session_open               (MegaSession* session, const gchar* password, const gchar* session_id, GError** error);
gboolean                mega_session_close              (MegaSession* session);

gboolean                mega_session_save               (MegaSession* session, GError** error);
gboolean                mega_session_load               (MegaSession* session, const gchar* username, const gchar* password, GError** error);

gchar*                  mega_session_register_anon      (MegaSession* session, const gchar* password, GError** error);
gchar*                  mega_session_register           (MegaSession* session, const gchar* email, const gchar* password, const gchar* name, GError** error);
gboolean                mega_session_register_verify    (MegaSession* session, const gchar* state, const gchar* signup_key, GError** error);

gchar*                  mega_session_get_info           (MegaSession* session, GError** error);

MegaApi*                mega_session_get_api            (MegaSession* session);
MegaAesKey*             mega_session_get_master_key     (MegaSession* session);
MegaRsaKey*             mega_session_get_rsa_key        (MegaSession* session);
const gchar*            mega_session_get_user_handle    (MegaSession* session);
MegaFilesystem*         mega_session_get_filesystem     (MegaSession* session);

gchar*                  mega_session_get_json           (MegaSession* session);
gboolean                mega_session_set_json           (MegaSession* session, const gchar* json);

gboolean                mega_session_is_fresh           (MegaSession* session, gint64 max_age);

G_END_DECLS

#endif
