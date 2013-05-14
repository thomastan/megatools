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
 * MegaFilesystem:
 *
 * Represents a Mega.co.nz filesystem - a tree of nodes addressable by path.
 */

#include <string.h>
#include <time.h>
#include "mega-filesystem.h"
#include "mega-session.h"
#include "mega-api.h"
#include "mega-node.h"
#include "private-utils.h"

struct _MegaFilesystemPrivate
{
  MegaSession* session;

  GHashTable* share_keys;
  GSList* nodes;
  GHashTable* pathmap;
  gint64 last_refresh;
};

// {{{ GObject property and signal enums

enum MegaFilesystemProp
{
  PROP_0,
  PROP_SESSION,
  N_PROPERTIES
};

enum MegaFilesystemSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

static gboolean handle_auth(const gchar* handle, const gchar* b64_ha, MegaAesKey* master_key)
{
  gsize ha_len = 0;
  gboolean status;

  g_return_val_if_fail(handle != NULL, FALSE);
  g_return_val_if_fail(b64_ha != NULL, FALSE);
  g_return_val_if_fail(master_key != NULL, FALSE);

  GBytes* ha = mega_aes_key_decrypt(master_key, b64_ha);
  if (!ha || g_bytes_get_size(ha) != 16)
  {
    g_bytes_unref(ha);
    return FALSE;
  }

  const gchar* ha_data = g_bytes_get_data(ha, NULL);
  status = !memcmp(ha_data, handle, 8) && !memcmp(ha_data + 8, handle, 8);
  g_bytes_unref(ha);

  return status;
}

static void build_pathmap(MegaFilesystem* filesystem, MegaNode* parent, const gchar* base_path)
{
  MegaFilesystemPrivate* priv = filesystem->priv;
  GSList* i;

  for (i = priv->nodes; i; i = i->next)
  {
    MegaNode* node = i->data;

    if (mega_node_is_child(node, parent))
    {
      gchar* path = g_strdup_printf("%s/%s", base_path, mega_node_get_name(node));

      // handle dups
      if (g_hash_table_lookup(priv->pathmap, path))
      {
        gchar* tmp = g_strconcat(path, ".", mega_node_get_handle(node), NULL);
        g_free(path);
        path = tmp;
      }

      g_object_set(node, "path", path, NULL);
      g_hash_table_insert(priv->pathmap, path, g_object_ref(node));

      build_pathmap(filesystem, node, path);
    }
  }
}

static void update_pathmap(MegaFilesystem* filesystem)
{
  g_return_if_fail(MEGA_IS_FILESYSTEM(filesystem));

  g_hash_table_remove_all(filesystem->priv->pathmap);
  build_pathmap(filesystem, NULL, "");
}

static gchar* path_sanitize_slashes(const gchar* path)
{
  g_return_val_if_fail(path != NULL, NULL);

  gchar* sanepath = g_malloc(strlen(path) + 1);
  gchar* tmp = sanepath;
  gboolean previous_was_slash = 0;

  while (*path != '\0')
  {
    if (*path != '/' || !previous_was_slash)
      *(tmp++) = *path;

    previous_was_slash = *path == '/' ? 1 : 0;
    path++;
  }

  *tmp = '\0';
  if (tmp > (sanepath + 1) && *(tmp - 1) == '/')
    *(tmp-1) = '\0';

  return sanepath;
}

static gchar** path_get_elements(const gchar* path)
{
  g_return_val_if_fail(path != NULL, NULL);

  gchar* sane_path = path_sanitize_slashes(path); /* always succeeds */
  gchar** pathv = g_strsplit(sane_path, "/", 0);
  g_free(sane_path);

  return pathv;
}

G_GNUC_UNUSED
static gchar* path_simplify(const gchar* path)
{
  gchar **pathv, **sane_pathv;
  guint i, j = 0, pathv_len, subroot = 0;
  gboolean absolute;

  g_return_val_if_fail(path != NULL, NULL);
  
  pathv = path_get_elements(path); /* should free */
  pathv_len = g_strv_length(pathv);
  
  sane_pathv = (gchar**)g_malloc0((pathv_len + 1) * sizeof(gchar*));
  absolute = (pathv_len > 1 && **pathv == '\0');
  
  for (i = 0; i < pathv_len; i++)
  {
    if (!strcmp(pathv[i], "."))
      continue; /* ignore curdirs in path */
    else if (!strcmp(pathv[i], ".."))
    {
      if (absolute)
      {
        if (j > 1)
        {
          j--;
        }
      }
      else
      {
        if (subroot && !strcmp(sane_pathv[j - 1], "..")) /* if we are off base and last item is .. */
        {
          sane_pathv[j++] = pathv[i];
        }
        else
        {
          if (j > subroot)
          {
            j--;
          }
          else
          {
            subroot++;
            sane_pathv[j++] = pathv[i];
          }
        }
      }
    }
    else
    {
      sane_pathv[j++] = pathv[i];
    }
  }

  sane_pathv[j] = 0;
  gchar* simple_path = g_strjoinv("/", sane_pathv);

  g_strfreev(pathv);
  g_free(sane_pathv);

  return simple_path;
}

/**
 * mega_filesystem_new:
 *
 * Create new #MegaFilesystem object.
 *
 * Returns: #MegaFilesystem object.
 */
MegaFilesystem* mega_filesystem_new(MegaSession* session)
{
  MegaFilesystem *filesystem = g_object_new(MEGA_TYPE_FILESYSTEM, "session", session, NULL);

  return filesystem;
}

/**
 * mega_filesystem_clear:
 * @filesystem: a #MegaFilesystem
 *
 * Clear filesystem contents.
 */
void mega_filesystem_clear(MegaFilesystem* filesystem)
{
  MegaFilesystemPrivate* priv;

  g_return_if_fail(MEGA_IS_FILESYSTEM(filesystem));

  priv = filesystem->priv;

  g_hash_table_remove_all(priv->share_keys);
  g_hash_table_remove_all(priv->pathmap);

  g_slist_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
  priv->nodes = NULL;
}

/**
 * mega_filesystem_load:
 * @filesystem: a #MegaFilesystem
 * @error: Error.
 *
 * Load data into the filesystem from the session.
 *
 * Returns: TRUE on success.
 */
gboolean mega_filesystem_load(MegaFilesystem* filesystem, GError** error)
{
  MegaFilesystemPrivate* priv;
  MegaAesKey* master_key;
  GError* local_err = NULL;
  gchar* f_node;
  GSList* list = NULL;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = filesystem->priv;
  master_key = mega_session_get_master_key(priv->session);

  f_node = mega_api_call_simple(mega_session_get_api(priv->session), 'o', &local_err, "{a:f, c:1}");
  if (!f_node)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  // process 'ok' array

  const gchar* ok_array = s_json_path(f_node, ".ok!a");
  if (ok_array)
  {
    S_JSON_FOREACH_ELEMENT(ok_array, ok)
      if (s_json_get_type(ok) != S_JSON_TYPE_OBJECT)
        continue;

      gchar* h = s_json_get_member_string(ok, "h");    // h.8 
      gchar* ha = s_json_get_member_string(ok, "ha");  // b64(aes(h.8 h.8, master_key))
      gchar* k = s_json_get_member_string(ok, "k");    // b64(aes(share_key_for_h, master_key))

      if (h && ha && k)
      {
        if (handle_auth(h, ha, master_key))
        {
          MegaAesKey* key = mega_aes_key_new_from_enc_ubase64(k, master_key);
          mega_filesystem_add_share_key(filesystem, h, key);
          g_object_unref(key);
        }
        else
          g_printerr("WARNING: Skipping import of a key %s because its authentication failed\n", h);
      }
      else
        g_printerr("WARNING: Skipping import of a key %s because it is missing required attributes\n", h);

      g_free(h);
      g_free(ha);
      g_free(k);
    S_JSON_FOREACH_END()
  }

  // process 'f' array

  const gchar* f_array = s_json_path(f_node, ".f!a");
  if (f_array)
  {
    S_JSON_FOREACH_ELEMENT(f_array, f)
      if (s_json_get_type(f) != S_JSON_TYPE_OBJECT)
        continue;

      MegaNode* node = mega_node_new(filesystem);
      if (mega_node_load(node, f, &local_err))
        list = g_slist_prepend(list, node);
      else
      {
        g_printerr("WARNING: Skipping import of node: %s\n", local_err->message ? local_err->message : "?");
        g_clear_error(&local_err);
        g_object_unref(node);
      }
    S_JSON_FOREACH_END()
  }

  // import special root node for contacts
  list = g_slist_prepend(list, mega_node_new_contacts(filesystem));

  // process 'u' array

  const gchar* u_array = s_json_path(f_node, ".u!a");
  if (u_array)
  {
    S_JSON_FOREACH_ELEMENT(u_array, u)
      if (s_json_get_type(u) != S_JSON_TYPE_OBJECT)
        continue;

      // skip self and removed
      gint64 c = s_json_get_member_int(u, "c", 0);
      if (c != 1)
        continue;

      MegaNode* node = mega_node_new(filesystem);
      if (mega_node_load_user(node, u, &local_err))
        list = g_slist_prepend(list, node);
      else
      {
        g_printerr("WARNING: Skipping import of node: %s\n", local_err->message ? local_err->message : "?");
        g_clear_error(&local_err);
        g_object_unref(node);
      }
    S_JSON_FOREACH_END()
  }

  g_free(f_node);

  g_slist_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
  priv->nodes = g_slist_reverse(list);

  update_pathmap(filesystem);

  priv->last_refresh = time(NULL);

  return TRUE;
}

/**
 * mega_filesystem_add_share_key:
 * @filesystem: a #MegaFilesystem
 * @handle: Key handle.
 * @key: AES key.
 *
 * Add key that can be used to decrypt node key.
 */
void mega_filesystem_add_share_key(MegaFilesystem* filesystem, const gchar* handle, MegaAesKey* key)
{
  MegaFilesystemPrivate* priv;

  g_return_if_fail(MEGA_IS_FILESYSTEM(filesystem));
  g_return_if_fail(handle != NULL);
  g_return_if_fail(MEGA_IS_AES_KEY(key));

  priv = filesystem->priv;

  g_hash_table_insert(priv->share_keys, g_strdup(handle), g_object_ref(key));
}

/**
 * mega_filesystem_get_share_key:
 * @filesystem: a #MegaFilesystem
 * @handle: Key handle.
 *
 * Get key that can be used to decrypt node key.
 *
 * Returns: (transfer none): AES key.
 */
MegaAesKey* mega_filesystem_get_share_key(MegaFilesystem* filesystem, const gchar* handle)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);
  g_return_val_if_fail(handle != NULL, NULL);

  priv = filesystem->priv;

  return g_hash_table_lookup(priv->share_keys, handle);
}

/**
 * mega_filesystem_get_session:
 * @filesystem: a #MegaFilesystem
 *
 * Get session associated with the filesystem.
 *
 * Returns: (transfer none): Session.
 */
MegaSession* mega_filesystem_get_session(MegaFilesystem* filesystem)
{
  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);

  return filesystem->priv->session;
}

static void share_key_to_json(gchar* handle, MegaAesKey* key, SJsonGen* gen)
{
  s_json_gen_start_object(gen);
  s_json_gen_member_string(gen, "handle", handle);
  s_json_gen_member_build(gen, "key", "%S", mega_aes_key_get_ubase64(key));
  s_json_gen_end_object(gen);
}

static void node_to_json(MegaNode* node, SJsonGen* gen)
{
  s_json_gen_build(gen, "%J", mega_node_get_json(node));
}

/**
 * mega_filesystem_get_json:
 * @filesystem: a #MegaFilesystem
 *
 * Serialize filesystem into JSON.
 *
 * Returns: JSON string.
 */
gchar* mega_filesystem_get_json(MegaFilesystem* filesystem)
{
  MegaFilesystemPrivate* priv;
  SJsonGen* gen;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);

  priv = filesystem->priv;

  gen = s_json_gen_new();
  s_json_gen_start_object(gen);

  s_json_gen_member_array(gen, "share_keys");
  g_hash_table_foreach(priv->share_keys, (GHFunc)share_key_to_json, gen);
  s_json_gen_end_array(gen);

  s_json_gen_member_array(gen, "nodes");
  g_slist_foreach(priv->nodes, (GFunc)node_to_json, gen);
  s_json_gen_end_array(gen);

  s_json_gen_member_int(gen, "last_refresh", priv->last_refresh);

  s_json_gen_end_object(gen);
  return s_json_gen_done(gen);
}

/**
 * mega_filesystem_set_json:
 * @filesystem: a #MegaFilesystem
 * @json: JSON string.
 *
 * Load filesystem data from JSON generated by #mega_filesystem_get_json.
 *
 * Returns: TRUE on success.
 */
gboolean mega_filesystem_set_json(MegaFilesystem* filesystem, const gchar* json)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), FALSE);
  g_return_val_if_fail(json != NULL, FALSE);

  priv = filesystem->priv;

  mega_filesystem_clear(filesystem);

  const gchar* sk_array = s_json_get_member(json, "share_keys");
  if (s_json_get_type(sk_array) != S_JSON_TYPE_ARRAY)
    return FALSE;

  const gchar* nodes_array = s_json_get_member(json, "nodes");
  if (s_json_get_type(nodes_array) != S_JSON_TYPE_ARRAY)
    return FALSE;

  // set share_keys

  S_JSON_FOREACH_ELEMENT(sk_array, sk)
    gchar* handle = s_json_get_member_string(sk, "handle");
    MegaAesKey* key = s_json_get_member_aes_key(sk, "key");

    mega_filesystem_add_share_key(filesystem, handle, key);

    g_object_unref(key);
    g_free(handle);
  S_JSON_FOREACH_END()

  // set nodes

  S_JSON_FOREACH_ELEMENT(nodes_array, n)
    MegaNode* node = mega_node_new(filesystem);

    if (mega_node_set_json(node, n))
      priv->nodes = g_slist_prepend(priv->nodes, node);
    else
      g_object_unref(node);
  S_JSON_FOREACH_END()

  priv->nodes = g_slist_reverse(priv->nodes);

  priv->last_refresh = s_json_get_member_int(json, "last_refresh", 0);

  update_pathmap(filesystem);

  return TRUE;
}

/**
 * mega_filesystem_is_fresh:
 * @filesystem: a #MegaFilesystem
 * @max_age: Maximum age in seconds.
 *
 * Check if the filesystem data are not older than #max_age.
 *
 * Returns: TRUE if filesystem is fresh.
 */
gboolean mega_filesystem_is_fresh(MegaFilesystem* filesystem, gint64 max_age)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), FALSE);
  g_return_val_if_fail(max_age >= 0, FALSE);

  priv = filesystem->priv;

  return priv->last_refresh > 0 && (priv->last_refresh + max_age) >= time(NULL);
}

// {{{ GObject type setup

static void mega_filesystem_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaFilesystem* filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  switch (property_id)
  {
    case PROP_SESSION:
      g_clear_object(&priv->session);
      priv->session = g_value_dup_object(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_filesystem_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaFilesystem* filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  switch (property_id)
  {
    case PROP_SESSION:
      g_value_set_object(value, priv->session);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaFilesystem, mega_filesystem, G_TYPE_OBJECT);

static void mega_filesystem_init(MegaFilesystem *filesystem)
{
  filesystem->priv = G_TYPE_INSTANCE_GET_PRIVATE(filesystem, MEGA_TYPE_FILESYSTEM, MegaFilesystemPrivate);

  filesystem->priv->pathmap = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
  filesystem->priv->share_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void mega_filesystem_dispose(GObject *object)
{
  MegaFilesystem *filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  g_clear_object(&priv->session);
  g_hash_table_remove_all(priv->pathmap);

  G_OBJECT_CLASS(mega_filesystem_parent_class)->dispose(object);
}

static void mega_filesystem_finalize(GObject *object)
{
  MegaFilesystem *filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  g_slist_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
  priv->nodes = NULL;

  g_hash_table_destroy(priv->pathmap);
  g_hash_table_destroy(priv->share_keys);

  G_OBJECT_CLASS(mega_filesystem_parent_class)->finalize(object);
}

static void mega_filesystem_class_init(MegaFilesystemClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_filesystem_set_property;
  gobject_class->get_property = mega_filesystem_get_property;
  gobject_class->dispose = mega_filesystem_dispose;
  gobject_class->finalize = mega_filesystem_finalize;

  g_type_class_add_private(klass, sizeof(MegaFilesystemPrivate));

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "session",
    /* nick    */ "Session",
    /* blurb   */ "Get session",
    /* is_type */ MEGA_TYPE_SESSION,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY
  );

  g_object_class_install_property(gobject_class, PROP_SESSION, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

gint mega_filesystem_error_quark(void)
{
  return g_quark_from_static_string("mega-filesystem-error-quark");
}

// }}}
