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

/*
 * Filesystem nodes tree
 * ---------------------
 *
 * Filesystem holds a list of all nodes. There are two representations of
 * relations between nodes: 
 *
 *   - Mega.co.nz node handles (handle, parent_handle, su_handle).
 *   - MegaNode pointers (parent/children)
 *
 * These representations may differ, and can be synchronized. This allows
 * for reorganizations of the tree in memory and sending batch change requests
 * to the server.
 *
 * In order to perform filesystem changes, user would modify the node tree,
 * and call #mega_filesystem_sync method.
 */

struct _MegaFilesystemPrivate
{
  GWeakRef session;

  GList* nodes;

  // optimization for fast access to individual/root nodes
  GSList* root_nodes;
  GHashTable* pathmap;
  GHashTable* handlemap;

  GHashTable* share_keys;
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

static void build_pathmap(MegaFilesystem* filesystem, GList** nodes, MegaNode* parent, const gchar* base_path)
{
  MegaFilesystemPrivate* priv = filesystem->priv;
  GList *i, *next, *matched = NULL;

  if (parent)
    mega_node_remove_children(parent);

  for (i = *nodes; i; i = next)
  {
    MegaNode* node = i->data;
    next = i->next;

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

      if (parent)
        mega_node_add_child(parent, node);
      g_object_set(node, "path", path, "parent", parent, NULL);
      g_hash_table_insert(priv->pathmap, g_strdup(path), g_object_ref(node));
      
      *nodes = g_list_remove_link(*nodes, i);
      matched = g_list_concat(matched, i);

      g_free(path);
    }

    // first iteration
    if (parent == NULL && mega_node_get_handle(node))
    {
      g_hash_table_insert(priv->handlemap, g_strdup(mega_node_get_handle(node)), g_object_ref(node));

      if (mega_node_is_child(node, NULL))
        priv->root_nodes = g_slist_prepend(priv->root_nodes, g_object_ref(node));
    }
  }

  for (i = matched; i; i = i->next)
    build_pathmap(filesystem, nodes, i->data, mega_node_get_path(i->data));

  g_list_free(matched);
}

static void update_maps(MegaFilesystem* filesystem)
{
  MegaFilesystemPrivate* priv;
  GList* nodes;

  g_return_if_fail(MEGA_IS_FILESYSTEM(filesystem));

  priv = filesystem->priv;

  // cleanup first
  g_hash_table_remove_all(priv->pathmap);
  g_hash_table_remove_all(priv->handlemap);
  g_slist_free_full(priv->root_nodes, g_object_unref);
  priv->root_nodes = NULL;

  // create a working copy of the node list
  nodes = g_list_copy(priv->nodes);
  build_pathmap(filesystem, &nodes, NULL, "");
  g_list_free(nodes);
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
  return g_object_new(MEGA_TYPE_FILESYSTEM, "session", session, NULL);
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
  g_hash_table_remove_all(priv->handlemap);

  g_list_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
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
  GList* list = NULL;
  MegaSession* session = NULL;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = filesystem->priv;
  session = mega_filesystem_get_session(filesystem);
  master_key = mega_session_get_master_key(session);

  if (!session || !master_key)
  {
    g_clear_object(&session);
    return FALSE;
  }

  f_node = mega_api_call_simple(mega_session_get_api(session), 'o', &local_err, "{a:f, c:1}");
  if (!f_node)
  {
    g_propagate_error(error, local_err);
    g_clear_object(&session);
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
        list = g_list_prepend(list, node);
      else
      {
        g_printerr("WARNING: Skipping import of node: %s\n", local_err->message ? local_err->message : "?");
        g_clear_error(&local_err);
        g_object_unref(node);
      }
    S_JSON_FOREACH_END()
  }

  // import special root node for contacts
  list = g_list_prepend(list, mega_node_new_contacts(filesystem));

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
        list = g_list_prepend(list, node);
      else
      {
        g_printerr("WARNING: Skipping import of node: %s\n", local_err->message ? local_err->message : "?");
        g_clear_error(&local_err);
        g_object_unref(node);
      }
    S_JSON_FOREACH_END()
  }

  g_free(f_node);

  g_list_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
  priv->nodes = g_list_reverse(list);

  update_maps(filesystem);

  priv->last_refresh = time(NULL);

  g_clear_object(&session);
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
 * Returns: (transfer full): Session.
 */
MegaSession* mega_filesystem_get_session(MegaFilesystem* filesystem)
{
  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);

  return g_weak_ref_get(&filesystem->priv->session);
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
  g_list_foreach(priv->nodes, (GFunc)node_to_json, gen);
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
      priv->nodes = g_list_prepend(priv->nodes, node);
    else
      g_object_unref(node);
  S_JSON_FOREACH_END()

  priv->nodes = g_list_reverse(priv->nodes);

  priv->last_refresh = s_json_get_member_int(json, "last_refresh", 0);

  update_maps(filesystem);

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

struct FilterData
{
  GSList* result;
  MegaNodeFilter filter;
  gpointer user_data;
};

static void filter_iter(MegaNode* node, struct FilterData* data)
{
  if (data->filter == NULL || data->filter(node, data->user_data))
    data->result = g_slist_prepend(data->result, g_object_ref(node));
}

/**
 * mega_filesystem_filter_nodes:
 * @filesystem: a #MegaFilesystem
 * @filter: (closure user_data) (scope call) (allow-none): Function that takes MegaNode and #user_data,
 * and should return #TRUE to include node to the returned result set.
 * @user_data: Arbitrary data to be passed to the filter function.
 *
 * Get list of nodes matching a filter.
 *
 * Returns: (transfer full) (element-type MegaNode): List of nodes.
 */
GSList* mega_filesystem_filter_nodes(MegaFilesystem* filesystem, MegaNodeFilter filter, gpointer user_data)
{
  MegaFilesystemPrivate* priv;
  struct FilterData iter_data;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);

  priv = filesystem->priv;

  iter_data.filter = filter;
  iter_data.user_data = user_data;
  iter_data.result = NULL;

  g_list_foreach(priv->nodes, (GFunc)filter_iter, &iter_data);

  return g_slist_reverse(iter_data.result);
}

/**
 * mega_filesystem_get_node_by_path:
 * @filesystem: a #MegaFilesystem
 * @path: Node path.
 *
 * Get node by path.
 *
 * Returns: (transfer none): a #MegaNode
 */
MegaNode* mega_filesystem_get_node_by_path(MegaFilesystem* filesystem, const gchar* path)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);
  g_return_val_if_fail(path != NULL, NULL);

  priv = filesystem->priv;

  return g_hash_table_lookup(priv->pathmap, path);
}

/**
 * mega_filesystem_get_node:
 * @filesystem: a #MegaFilesystem
 * @handle: Node handle.
 *
 * Get node by handle.
 *
 * Returns: (transfer none): a #MegaNode
 */
MegaNode* mega_filesystem_get_node(MegaFilesystem* filesystem, const gchar* handle)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);
  g_return_val_if_fail(handle != NULL, NULL);

  priv = filesystem->priv;

  return g_hash_table_lookup(priv->handlemap, handle);
}

/**
 * mega_filesystem_glob:
 * @filesystem: a #MegaFilesystem
 * @glob: A glob pattern
 *
 * Get list of nodes matching glob pattern.
 *
 * Returns: (transfer full) (element-type MegaNode): List of nodes.
 */
GSList* mega_filesystem_glob(MegaFilesystem* filesystem, const gchar* glob)
{
  gchar** glob_parts;
  GPtrArray* parts;
  gint i;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);
  g_return_val_if_fail(glob != NULL, NULL);

  // skip relative glob paterns
  glob_parts = g_regex_split_simple("/+", glob, 0, G_REGEX_MATCH_NOTEMPTY);
  if (glob_parts == NULL || glob_parts[0][0] != '\0')
    return NULL;

  // preprocess glob patern (.. and .)
  parts = g_ptr_array_sized_new(g_strv_length(glob_parts));
  for (i = 1; glob_parts[i]; i++)  
  {
    if (!strcmp(glob_parts[i], ".."))
    {
      if (parts->len > 0)
        g_ptr_array_remove_index(parts, parts->len - 1);
    }
    else if (strcmp(glob_parts[i], ".") && strcmp(glob_parts[i], ""))
      g_ptr_array_add(parts, glob_parts[i]);
  }

  // create list of root nodes filtered by pattern
  GSList *full_list = NULL, *filtered_list = NULL, *iter;
  for (i = 0; i < parts->len; i++)  
  {
    gchar* pattern = g_ptr_array_index(parts, i);

    // create list of nodes for filtering
    g_slist_free_full(full_list, g_object_unref);
    if (i == 0)
    {
      full_list = mega_filesystem_get_root_nodes(filesystem);
    }
    else
    {
      full_list = NULL;
      for (iter = filtered_list; iter; iter = iter->next)
      {
        MegaNode* node = iter->data;

        full_list = g_slist_concat(full_list, mega_node_get_children(node));
      }
    }

    // clear fitlered list
    g_slist_free_full(filtered_list, g_object_unref);
    filtered_list = NULL;

    for (iter = full_list; iter; iter = iter->next)
    {
      MegaNode* node = iter->data;

      if (g_pattern_match_simple(pattern, mega_node_get_name(node)))
        filtered_list = g_slist_prepend(filtered_list, g_object_ref(node));
    }
  }

  g_slist_free_full(full_list, g_object_unref);
  g_strfreev(glob_parts);
  g_ptr_array_unref(parts);

  return g_slist_reverse(filtered_list);
}

/**
 * mega_filesystem_get_root_nodes:
 * @filesystem: a #MegaFilesystem
 *
 * Get filesystem root nodes.
 *
 * Returns: (transfer full) (element-type MegaNode): List of nodes.
 */
GSList* mega_filesystem_get_root_nodes(MegaFilesystem* filesystem)
{
  MegaFilesystemPrivate* priv;

  g_return_val_if_fail(MEGA_IS_FILESYSTEM(filesystem), NULL);

  priv = filesystem->priv;

  return g_slist_copy_deep(priv->root_nodes, (GCopyFunc)g_object_ref, NULL);
}

// {{{ GObject type setup

static void mega_filesystem_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaFilesystem* filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  switch (property_id)
  {
    case PROP_SESSION:
      g_weak_ref_set(&priv->session, g_value_get_object(value));
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
      g_value_take_object(value, g_weak_ref_get(&priv->session));
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
  filesystem->priv->handlemap = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);
  filesystem->priv->share_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_object_unref);

  filesystem->priv->nodes = NULL;
  filesystem->priv->root_nodes = NULL;

  g_weak_ref_init(&filesystem->priv->session, NULL);
}

static void mega_filesystem_dispose(GObject *object)
{
  MegaFilesystem *filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  G_OBJECT_CLASS(mega_filesystem_parent_class)->dispose(object);
}

static void mega_filesystem_finalize(GObject *object)
{
  MegaFilesystem *filesystem = MEGA_FILESYSTEM(object);
  MegaFilesystemPrivate* priv = filesystem->priv;

  g_list_free_full(priv->nodes, (GDestroyNotify)g_object_unref);
  priv->nodes = NULL;

  g_slist_free_full(priv->root_nodes, (GDestroyNotify)g_object_unref);
  priv->root_nodes = NULL;

  g_hash_table_destroy(priv->pathmap);
  g_hash_table_destroy(priv->handlemap);
  g_hash_table_destroy(priv->share_keys);

  g_weak_ref_clear(&priv->session);

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
