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
 * MegaNode:
 *
 * Object that represents a filesystem node.
 */

#include <string.h>
#include "mega-node.h"
#include "mega-filesystem.h"
#include "mega-session.h"
#include "mega-rsa-key.h"
#include "mega-file-key.h"
#include "sjson.h"

struct _MegaNodePrivate
{
  MegaFilesystem* filesystem;

  gchar* name;
  gchar* handle;
  gchar* parent_handle;
  gchar* owner_handle;
  gchar* su_handle;
  MegaAesKey* key;
  gint64 timestamp;
  gint64 size;
  gint type;

  gchar* path;
  gchar* link;
};

// {{{ GObject property and signal enums

enum MegaNodeProp
{
  PROP_0,
  PROP_FILESYSTEM,
  PROP_NAME,
  PROP_HANDLE,
  PROP_PARENT_HANDLE,
  PROP_OWNER_HANDLE,
  PROP_SU_HANDLE,
  PROP_KEY,
  PROP_PATH,
  PROP_LINK,
  PROP_TIMESTAMP,
  PROP_SIZE,
  PROP_TYPE,
  N_PROPERTIES
};

enum MegaNodeSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

#if 0
static gchar* encode_node_attrs(const gchar* name)
{
  g_return_val_if_fail(name != NULL, NULL);

  gchar* attrs_json = s_json_build("{n:%s}", name);
  gchar* attrs = g_strconcat("MEGA", attrs_json, NULL);
  g_free(attrs_json);

  return attrs;
}
#endif

static gboolean decode_node_attrs(const gchar* attrs, gchar** name)
{
  g_return_val_if_fail(attrs != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  // parse attributes
  if (!attrs || !g_str_has_prefix(attrs, "MEGA{"))
    return FALSE;

  // decode JSON
  if (!s_json_is_valid(attrs + 4))
    return FALSE;

  *name = s_json_get_member_string(attrs + 4, "n");

  return TRUE;
}

static gboolean decrypt_node_attrs(const gchar* encrypted_attrs, MegaAesKey* key, gchar** name)
{
  gboolean status = FALSE;

  g_return_val_if_fail(encrypted_attrs != NULL, FALSE);
  g_return_val_if_fail(MEGA_IS_AES_KEY(key), FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  // attrs data are always zero terminated
  GBytes* attrs = mega_aes_key_decrypt_cbc(key, encrypted_attrs);
  if (attrs)
  {
    status = decode_node_attrs(g_bytes_get_data(attrs, NULL), name);
    g_bytes_unref(attrs);
  }

  return status;
}

static MegaRsaKey* get_session_rsa_key(MegaNode* node)
{
  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);

  return mega_session_get_rsa_key(mega_filesystem_get_session(node->priv->filesystem));
}

static MegaAesKey* get_session_master_key(MegaNode* node)
{
  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);

  return mega_session_get_master_key(mega_filesystem_get_session(node->priv->filesystem));
}

/**
 * mega_node_new:
 * @filesystem: (transfer none): a #MegaFilesystem
 *
 * Create new #MegaNode object.
 *
 * Returns: #MegaNode object.
 */
MegaNode* mega_node_new(MegaFilesystem* filesystem)
{
  return g_object_new(MEGA_TYPE_NODE, "filesystem", filesystem, NULL);
}

/**
 * mega_node_new_contacts:
 * @filesystem: (transfer none): a #MegaFilesystem
 *
 * Create a new #MegaNode object that represnts /Contacts folder.
 *
 * Returns: #MegaNode object.
 */
MegaNode* mega_node_new_contacts(MegaFilesystem* filesystem)
{
  return g_object_new(MEGA_TYPE_NODE,
    "filesystem", filesystem, 
    "name", "Contacts", 
    "handle", "NETWORK", 
    "type", MEGA_NODE_TYPE_NETWORK,
    NULL
  );
}

static MegaAesKey* decrypt_node_key(MegaNode* node, const gchar* k, GError** error)
{
  MegaNodePrivate* priv;
  const gchar* user_handle;
  MegaAesKey* key = NULL;
  gchar* encrypted_node_key = NULL;
  gchar** parts;
  gint i;

  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);
  g_return_val_if_fail(k != NULL, NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  priv = node->priv;
  user_handle = mega_session_get_user_handle(mega_filesystem_get_session(priv->filesystem));

  // parse k = 'handle1:key1/handle2:key2/...' and find suitable decryption key

  parts = g_strsplit(k, "/", 0);

  for (i = 0; parts[i]; i++)
  {
    gchar* key_value = strchr(parts[i], ':');
    if (key_value)
    {
      gchar* key_handle = parts[i];
      *key_value = '\0'; 
      key_value++;

      if (user_handle && !strcmp(user_handle, key_handle))
      {
        // we found a key encrypted by me
        encrypted_node_key = g_strdup(key_value);
        key = get_session_master_key(node);
        break;
      }

      key = mega_filesystem_get_share_key(priv->filesystem, key_handle);
      if (key)
      {
        encrypted_node_key = g_strdup(key_value);
        break;
      }
    }
  }

  g_strfreev(parts);

  // check that we got the key

  if (!encrypted_node_key)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Decryption key for node key not found");
    return NULL;
  }

  // keys longer than 45 chars are RSA keys, skip

  if (strlen(encrypted_node_key) >= 46)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "RSA node key not supported");
    goto err;
  }

  if (priv->type == MEGA_NODE_TYPE_FILE)
  {
    MegaFileKey* node_key = mega_file_key_new();
    if (!mega_file_key_load_enc_ubase64(node_key, encrypted_node_key, key))
    {
      g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Can't decrypt file key");
      g_object_unref(node_key);
      goto err;
    }
    
    g_free(encrypted_node_key);
    return MEGA_AES_KEY(node_key);
  }
  else
  {
    MegaAesKey* node_key = mega_aes_key_new_from_enc_ubase64(encrypted_node_key, key);
    if (!mega_aes_key_is_loaded(node_key))
    {
      g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Can't decrypt folder key");
      g_object_unref(node_key);
      goto err;
    }

    g_free(encrypted_node_key);
    return node_key;
  }

err:
  g_free(encrypted_node_key);
  return NULL;
}

/**
 * mega_node_load:
 * @node: a #MegaNode
 * @json: Mega.co.nz node JSON object.
 * @error: Error.
 *
 * Load node data from the JSON object that is returned from 'f' API call.
 *
 * Node is in undefined state after failed load.
 *
 * Returns: TRUE on success.
 */
gboolean mega_node_load(MegaNode* node, const gchar* json, GError** error)
{
  GError* local_err = NULL;
  MegaNodePrivate* priv;

  g_return_val_if_fail(MEGA_IS_NODE(node), FALSE);
  g_return_val_if_fail(json != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = node->priv;

  // sanity checks

  if (s_json_get_type(json) != S_JSON_TYPE_OBJECT)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Invalid JSON data");
    return FALSE;
  }

  const gchar* handle = s_json_path(json, ".h!s");
  if (!handle)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Missing handle");
    return FALSE;
  }

  mega_node_clear(node);

  priv->handle = s_json_get_string(handle);
  priv->type = s_json_get_member_int(json, "t", -1);
  priv->parent_handle = s_json_get_member_string(json, "p");
  if (priv->parent_handle && strlen(priv->parent_handle) == 0)
    g_clear_pointer(&priv->parent_handle, g_free);
  priv->owner_handle = s_json_get_member_string(json, "u");
  priv->su_handle = s_json_get_member_string(json, "su");
  priv->size = s_json_get_member_int(json, "s", -1);
  priv->timestamp = s_json_get_member_int(json, "ts", 0);

  // handle share keys

  gchar* sk = s_json_get_member_string(json, "sk");
  if (sk && strlen(sk) > 0)
  {
    GBytes* share_key;

    if (strlen(sk) > 22)
      share_key = mega_rsa_key_decrypt(get_session_rsa_key(node), sk);
    else
      share_key = mega_aes_key_decrypt(get_session_master_key(node), sk);

    if (share_key && g_bytes_get_size(share_key) >= 16)
    {
      MegaAesKey* aes_share_key = mega_aes_key_new_from_binary(g_bytes_get_data(share_key, NULL));
      mega_filesystem_add_share_key(priv->filesystem, priv->handle, aes_share_key);
      g_object_unref(aes_share_key);
    }

    g_bytes_unref(share_key);
  }

  g_free(sk);

  // handle special node types

  if (priv->type == MEGA_NODE_TYPE_ROOT)
  {
    priv->name = g_strdup("Root");
    return TRUE;
  }
  else if (priv->type == MEGA_NODE_TYPE_INBOX)
  {
    priv->name = g_strdup("Inbox");
    return TRUE;
  }
  else if (priv->type == MEGA_NODE_TYPE_TRASH)
  {
    priv->name = g_strdup("Trash");
    return TRUE;
  } 
  else if (priv->type != MEGA_NODE_TYPE_FOLDER && priv->type != MEGA_NODE_TYPE_FILE)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Unknown node type %d", priv->type);
    return FALSE;
  }

  // decrypt file or folder key

  gchar* k = s_json_get_member_string(json, "k");
  if (!k || strlen(k) == 0)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Missing node key");
    g_free(k);
    return FALSE;
  }

  priv->key = decrypt_node_key(node, k, &local_err);
  g_free(k);

  if (!priv->key)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  // decrypt attributes

  gchar* a = s_json_get_member_string(json, "a");
  if (!a || strlen(a) == 0)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Node attributes are missing");
    g_free(a);
    return FALSE;
  }

  // decrypt attributes with node key
  if (!decrypt_node_attrs(a, priv->key, &priv->name))
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Node attributes are malformed");
    return FALSE;
  }

  if (!priv->name)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Node name is missing");
    return FALSE;
  }

  // check for invalid characters in the name
  const gchar* n = priv->name;
#ifdef G_OS_WIN32
  if (strpbrk(n, "/\\<>:\"|?*") || !strcmp(n, ".") || !strcmp(n, ".."))
#else
  if (strpbrk(n, "/") || !strcmp(n, ".") || !strcmp(n, "..")) 
#endif
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Node name contains invalid characters %s", n);
    return FALSE;
  }

  return TRUE;
}

/**
 * mega_node_load_user:
 * @node: a #MegaNode
 * @json: Mega.co.nz contact JSON object.
 * @error: Error.
 *
 * Load contact data from the JSON object that is returned from 'f' API call.
 *
 * Node is in undefined state after failed load.
 *
 * Returns: TRUE on success.
 */
gboolean mega_node_load_user(MegaNode* node, const gchar* json, GError** error)
{
  MegaNodePrivate* priv;

  g_return_val_if_fail(MEGA_IS_NODE(node), FALSE);
  g_return_val_if_fail(json != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  priv = node->priv;

  mega_node_clear(node);

  priv->handle = s_json_get_member_string(json, "u");
  priv->name = s_json_get_member_string(json, "m");
  priv->timestamp = s_json_get_member_int(json, "ts", 0);
  priv->parent_handle = g_strdup("NETWORK");
  priv->type = MEGA_NODE_TYPE_CONTACT;

  if (!priv->handle)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Missing contact handle");
    return FALSE;
  }

  if (!priv->name)
  {
    g_set_error(error, MEGA_NODE_ERROR, MEGA_NODE_ERROR_OTHER, "Missing contact name");
    return FALSE;
  }

  return TRUE;
}

/**
 * mega_node_is_child:
 * @node: a #MegaNode
 * @parent: (transfer none) (allow-none):
 *
 * Check if node is child of #parent.
 *
 * Returns: TRUE if #node is child of #parent or if it is at toplevel if #parent
 * is #NULL.
 */
gboolean mega_node_is_child(MegaNode* node, MegaNode* parent)
{
  g_return_val_if_fail(MEGA_IS_NODE(node), FALSE);
  g_return_val_if_fail(parent == NULL || MEGA_IS_NODE(parent), FALSE);

  MegaNodePrivate* p1 = node->priv;
  MegaNodePrivate* p2 = parent ? parent->priv : NULL;

  if (parent)
  {
    if (parent->priv->type == MEGA_NODE_TYPE_CONTACT)
      return node->priv->su_handle && parent->priv->handle && !strcmp(node->priv->su_handle, parent->priv->handle);

    return node->priv->parent_handle != NULL && parent->priv->handle != NULL && !strcmp(node->priv->parent_handle, parent->priv->handle);
  }
  else
    return node->priv->parent_handle == NULL;
}

/**
 * mega_node_get_handle:
 * @node: a #MegaNode
 *
 * Get node handle.
 *
 * Returns: Handle.
 */
const gchar* mega_node_get_handle(MegaNode* node)
{
  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);

  return node->priv->handle;
}

/**
 * mega_node_get_name:
 * @node: a #MegaNode
 *
 * Get node name.
 *
 * Returns: Name.
 */
const gchar* mega_node_get_name(MegaNode* node)
{
  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);

  return node->priv->name;
}

#if 0
gboolean mega_node_is_writable(mega_session* s, mega_node* n)
{
  g_return_val_if_fail(n != NULL, FALSE);

  return n->type == MEGA_NODE_CONTACT 
    || ((n->type == MEGA_NODE_FILE || n->type == MEGA_NODE_FOLDER) && !strcmp(s->user_handle, n->user_handle))
    || n->type == MEGA_NODE_ROOT
    || n->type == MEGA_NODE_NETWORK
    || n->type == MEGA_NODE_TRASH;
}
#endif

/**
 * mega_node_get_json:
 * @node: a #MegaNode
 *
 * Serialize node into JSON.
 *
 * Returns: JSON string.
 */
gchar* mega_node_get_json(MegaNode* node)
{
  MegaNodePrivate* priv;
  SJsonGen* gen;

  g_return_val_if_fail(MEGA_IS_NODE(node), NULL);

  priv = node->priv;

  gen = s_json_gen_new();
  s_json_gen_start_object(gen);

  s_json_gen_member_string(gen, "name", priv->name);
  s_json_gen_member_string(gen, "handle", priv->handle);
  s_json_gen_member_string(gen, "parent_handle", priv->parent_handle);
  s_json_gen_member_string(gen, "owner_handle", priv->owner_handle);
  s_json_gen_member_string(gen, "su_handle", priv->su_handle);

  if (MEGA_IS_FILE_KEY(priv->key))
    s_json_gen_member_build(gen, "file-key", "%S", mega_file_key_get_ubase64(MEGA_FILE_KEY(priv->key)));
  else if (MEGA_IS_AES_KEY(priv->key))
    s_json_gen_member_build(gen, "folder-key", "%S", mega_aes_key_get_ubase64(priv->key));

  s_json_gen_member_int(gen, "timestamp", priv->timestamp);
  s_json_gen_member_int(gen, "size", priv->size);
  s_json_gen_member_int(gen, "type", priv->type);

  s_json_gen_member_string(gen, "path", priv->path);
  s_json_gen_member_string(gen, "link", priv->link);

  s_json_gen_end_object(gen);
  return s_json_gen_done(gen);
}

/**
 * mega_node_set_json:
 * @node: a #MegaNode
 * @json: JSON string.
 *
 * Load node from JSON generated by #mega_node_get_json.
 *
 * Returns: TRUE on success.
 */
gboolean mega_node_set_json(MegaNode* node, const gchar* json)
{
  MegaNodePrivate* priv;
  gchar* str;

  g_return_val_if_fail(MEGA_IS_NODE(node), FALSE);
  g_return_val_if_fail(json != NULL, FALSE);

  priv = node->priv;

  mega_node_clear(node);

  priv->name = s_json_get_member_string(json, "name");
  priv->handle = s_json_get_member_string(json, "handle");
  priv->parent_handle = s_json_get_member_string(json, "parent_handle");
  priv->owner_handle = s_json_get_member_string(json, "owner_handle");
  priv->su_handle = s_json_get_member_string(json, "su_handle");
  priv->type = s_json_get_member_int(json, "type", -1);
  priv->size = s_json_get_member_int(json, "size", -1);
  priv->timestamp = s_json_get_member_int(json, "timestamp", 0);
  priv->link = s_json_get_member_string(json, "link");

  str = s_json_get_member_string(json, "file-key");
  if (str)
  {
    priv->key = MEGA_AES_KEY(mega_file_key_new());
    if (!mega_file_key_load_ubase64(MEGA_FILE_KEY(priv->key), str))
    {
      g_free(str);
      return FALSE;
    }

    g_free(str);
  }

  str = s_json_get_member_string(json, "folder-key");
  if (str)
  {
    priv->key = mega_aes_key_new_from_ubase64(str);
    g_free(str);

    if (!mega_aes_key_is_loaded(priv->key))
      return FALSE;
  }

  if (priv->type < 0 || priv->handle == NULL || priv->name == NULL)
    return FALSE;

  if ((priv->type == MEGA_NODE_TYPE_FILE || priv->type == MEGA_NODE_TYPE_FOLDER) && !priv->key)
    return FALSE;

  return TRUE;
}

/**
 * mega_node_clear:
 * @node: a #MegaNode
 *
 * Clear node data.
 */
void mega_node_clear(MegaNode* node)
{
  MegaNodePrivate* priv;

  g_return_if_fail(MEGA_IS_NODE(node));

  priv = node->priv;

  priv->timestamp = 0;
  priv->type = -1;
  priv->size = -1;

  g_clear_pointer(&priv->name, g_free);
  g_clear_pointer(&priv->handle, g_free);
  g_clear_pointer(&priv->parent_handle, g_free);
  g_clear_pointer(&priv->owner_handle, g_free);
  g_clear_pointer(&priv->su_handle, g_free);

  g_clear_pointer(&priv->path, g_free);
  g_clear_pointer(&priv->link, g_free);

  g_clear_object(&priv->key);
}

// {{{ GObject type setup

static void mega_node_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaNode* node = MEGA_NODE(object);
  MegaNodePrivate* priv = node->priv;

  switch (property_id)
  {
    case PROP_FILESYSTEM:
      g_clear_object(&priv->filesystem);
      priv->filesystem = g_value_dup_object(value);
      break;

    case PROP_NAME:
      g_free(priv->name);
      priv->name = g_value_dup_string(value);
      break;

    case PROP_HANDLE:
      g_free(priv->handle);
      priv->handle = g_value_dup_string(value);
      break;

    case PROP_PARENT_HANDLE:
      g_free(priv->parent_handle);
      priv->parent_handle = g_value_dup_string(value);
      break;

    case PROP_OWNER_HANDLE:
      g_free(priv->owner_handle);
      priv->owner_handle = g_value_dup_string(value);
      break;

    case PROP_SU_HANDLE:
      g_free(priv->su_handle);
      priv->su_handle = g_value_dup_string(value);
      break;

    case PROP_KEY:
      g_clear_object(&priv->key);
      priv->key = g_value_dup_object(value);
      break;

    case PROP_PATH:
      g_free(priv->path);
      priv->path = g_value_dup_string(value);
      break;

    case PROP_LINK:
      g_free(priv->link);
      priv->link = g_value_dup_string(value);
      break;

    case PROP_TIMESTAMP:
      priv->timestamp = g_value_get_int64(value);
      break;

    case PROP_SIZE:
      priv->size = g_value_get_int64(value);
      break;

    case PROP_TYPE:
      priv->type = g_value_get_int(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_node_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaNode* node = MEGA_NODE(object);
  MegaNodePrivate* priv = node->priv;

  switch (property_id)
  {
    case PROP_FILESYSTEM:
      g_value_set_object(value, priv->filesystem);
      break;

    case PROP_NAME:
      g_value_set_string(value, priv->name);
      break;

    case PROP_HANDLE:
      g_value_set_string(value, priv->handle);
      break;

    case PROP_PARENT_HANDLE:
      g_value_set_string(value, priv->parent_handle);
      break;

    case PROP_OWNER_HANDLE:
      g_value_set_string(value, priv->owner_handle);
      break;

    case PROP_SU_HANDLE:
      g_value_set_string(value, priv->su_handle);
      break;

    case PROP_KEY:
      g_value_set_object(value, priv->key);
      break;

    case PROP_PATH:
      g_value_set_string(value, priv->path);
      break;

    case PROP_LINK:
      g_value_set_string(value, priv->link);
      break;

    case PROP_TIMESTAMP:
      g_value_set_int64(value, priv->timestamp);
      break;

    case PROP_SIZE:
      g_value_set_int64(value, priv->size);
      break;

    case PROP_TYPE:
      g_value_set_int(value, priv->type);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaNode, mega_node, G_TYPE_OBJECT);

static void mega_node_init(MegaNode *node)
{
  node->priv = G_TYPE_INSTANCE_GET_PRIVATE(node, MEGA_TYPE_NODE, MegaNodePrivate);
}

static void mega_node_dispose(GObject *object)
{
  MegaNode *node = MEGA_NODE(object);
  MegaNodePrivate* priv = node->priv;

  g_clear_object(&priv->filesystem);

  G_OBJECT_CLASS(mega_node_parent_class)->dispose(object);
}

static void mega_node_finalize(GObject *object)
{
  MegaNode *node = MEGA_NODE(object);
  MegaNodePrivate* priv = node->priv;

  g_clear_pointer(&priv->name, g_free);
  g_clear_pointer(&priv->handle, g_free);
  g_clear_pointer(&priv->parent_handle, g_free);
  g_clear_pointer(&priv->owner_handle, g_free);
  g_clear_pointer(&priv->su_handle, g_free);
  g_clear_object(&priv->key);
  g_clear_pointer(&priv->path, g_free);
  g_clear_pointer(&priv->link, g_free);

  G_OBJECT_CLASS(mega_node_parent_class)->finalize(object);
}

static void mega_node_class_init(MegaNodeClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_node_set_property;
  gobject_class->get_property = mega_node_get_property;
  gobject_class->dispose = mega_node_dispose;
  gobject_class->finalize = mega_node_finalize;

  g_type_class_add_private(klass, sizeof(MegaNodePrivate));

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "filesystem",
    /* nick    */ "Filesystem",
    /* blurb   */ "Get filesystem",
    /* is_type */ MEGA_TYPE_FILESYSTEM,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY
  );

  g_object_class_install_property(gobject_class, PROP_FILESYSTEM, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "name",
    /* nick    */ "Name",
    /* blurb   */ "Set/get name",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_NAME, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "handle",
    /* nick    */ "Handle",
    /* blurb   */ "Set/get handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_HANDLE, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "parent-handle",
    /* nick    */ "Parent-handle",
    /* blurb   */ "Set/get parent-handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_PARENT_HANDLE, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "owner-handle",
    /* nick    */ "Owner-handle",
    /* blurb   */ "Set/get owner-handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_OWNER_HANDLE, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "su-handle",
    /* nick    */ "Su-handle",
    /* blurb   */ "Set/get su-handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_SU_HANDLE, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "key",
    /* nick    */ "Key",
    /* blurb   */ "Set/get key",
    /* is_type */ MEGA_TYPE_AES_KEY,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_KEY, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "path",
    /* nick    */ "Path",
    /* blurb   */ "Set/get path",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_PATH, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "link",
    /* nick    */ "Link",
    /* blurb   */ "Set/get link",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_LINK, param_spec);

  param_spec = g_param_spec_int64(
    /* name    */ "timestamp",
    /* nick    */ "Timestamp",
    /* blurb   */ "Set/get timestamp",
    /* minimum */ 0,
    /* maximum */ G_MAXINT64,
    /* default */ 0,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_TIMESTAMP, param_spec);

  param_spec = g_param_spec_int64(
    /* name    */ "size",
    /* nick    */ "Size",
    /* blurb   */ "Set/get size",
    /* minimum */ -1,
    /* maximum */ G_MAXINT64,
    /* default */ -1,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_SIZE, param_spec);

  param_spec = g_param_spec_int(
    /* name    */ "type",
    /* nick    */ "Type",
    /* blurb   */ "Set/get type",
    /* minimum */ G_MININT32,
    /* maximum */ G_MAXINT32,
    /* default */ 0,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_TYPE, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

gint mega_node_error_quark(void)
{
  return g_quark_from_static_string("mega-node-error-quark");
}

// }}}
