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

#ifndef __MEGA_FILESYSTEM_H__
#define __MEGA_FILESYSTEM_H__

#include <mega/megatypes.h>
#include <mega/mega-aes-key.h>

#define MEGA_TYPE_FILESYSTEM            (mega_filesystem_get_type())
#define MEGA_FILESYSTEM(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_FILESYSTEM, MegaFilesystem))
#define MEGA_FILESYSTEM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_FILESYSTEM, MegaFilesystemClass))
#define MEGA_IS_FILESYSTEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_FILESYSTEM))
#define MEGA_IS_FILESYSTEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_FILESYSTEM))
#define MEGA_FILESYSTEM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_FILESYSTEM, MegaFilesystemClass))
#define MEGA_FILESYSTEM_ERROR           mega_filesystem_error_quark()

typedef struct _MegaFilesystemClass MegaFilesystemClass;
typedef struct _MegaFilesystemPrivate MegaFilesystemPrivate;

struct _MegaFilesystem
{
  GObject parent;
  MegaFilesystemPrivate* priv;
};

struct _MegaFilesystemClass
{
  GObjectClass parent_class;
};

typedef enum
{
  MEGA_FILESYSTEM_ERROR_OTHER
} MegaFilesystemError;

G_BEGIN_DECLS

GType                   mega_filesystem_get_type        (void) G_GNUC_CONST;
gint                    mega_filesystem_error_quark     (void) G_GNUC_CONST;

MegaFilesystem*         mega_filesystem_new             (MegaSession* session);
void                    mega_filesystem_clear           (MegaFilesystem* filesystem);
gboolean                mega_filesystem_load            (MegaFilesystem* filesystem, GError** error);

void                    mega_filesystem_add_share_key   (MegaFilesystem* filesystem, const gchar* user_handle, MegaAesKey* key);
MegaAesKey*             mega_filesystem_get_share_key   (MegaFilesystem* filesystem, const gchar* handle);

MegaSession*            mega_filesystem_get_session     (MegaFilesystem* filesystem);

gchar*                  mega_filesystem_get_json        (MegaFilesystem* filesystem);
gboolean                mega_filesystem_set_json        (MegaFilesystem* filesystem, const gchar* json);
gboolean                mega_filesystem_is_fresh        (MegaFilesystem* filesystem, gint64 max_age);

G_END_DECLS

#endif
