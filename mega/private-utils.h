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

#include "sjson.h"
#include "mega-aes-key.h"

G_GNUC_UNUSED
static MegaAesKey* s_json_get_member_aes_key(const gchar* json, const gchar* member)
{
  gchar* str = s_json_get_member_string(json, member);
  MegaAesKey* key = mega_aes_key_new_from_ubase64(str);
  g_free(str);

  if (mega_aes_key_is_loaded(key))
    return key;

  g_object_unref(key);
  return NULL;
}
