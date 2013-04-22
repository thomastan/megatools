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

#include "oldmega.h"
#include "sjson.h"

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// {{{ add_share_key

// }}}

// {{{ mega_session_addlinks

gboolean mega_session_addlinks(mega_session* s, GSList* nodes, GError** err)
{
  GError* local_err = NULL;
  GSList* i;
  GPtrArray* rnodes;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  if (g_slist_length(nodes) == 0)
    return TRUE;

  rnodes = g_ptr_array_sized_new(g_slist_length(nodes));

  // prepare request
  SJsonGen *gen = s_json_gen_new();
  s_json_gen_start_array(gen);
  for (i = nodes; i; i = i->next)
  {
    mega_node* n = i->data;

    if (n->type == MEGA_NODE_FILE)
    {
      s_json_gen_start_object(gen);
      s_json_gen_member_string(gen, "a", "l");
      s_json_gen_member_string(gen, "n", n->handle);
      s_json_gen_end_object(gen);

      g_ptr_array_add(rnodes, n);
    }
  }
  s_json_gen_end_array(gen);
  gchar *request = s_json_gen_done(gen);

  // perform request
  gchar* response = api_request(s, request, &local_err);
  g_free(request);

  // process response
  if (!response)
  {
    g_propagate_prefixed_error(err, local_err, "API call 'l' failed: ");
    g_ptr_array_free(rnodes, TRUE);
    return FALSE;
  }
  
  if (s_json_get_type(response) == S_JSON_TYPE_ARRAY)
  {
    gchar** nodes_arr = s_json_get_elements(response);
    gint i, l = g_strv_length(nodes_arr);

    if (l != rnodes->len)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "API call 'l' results mismatch");
      g_ptr_array_free(rnodes, TRUE);
      g_free(nodes_arr);
      g_free(response);
      return FALSE;
    }

    for (i = 0; i < l; i++)
    {
      gchar* link = s_json_get_string(nodes_arr[i]);

      mega_node* n = g_ptr_array_index(rnodes, i);

      g_free(n->link);
      n->link = link;
    }

    g_free(nodes_arr);
  }

  g_free(response);
  g_ptr_array_free(rnodes, TRUE);

  return TRUE;
}

// }}}
// {{{ mega_session_user_quota

mega_user_quota* mega_session_user_quota(mega_session* s, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  // prepare request
  gchar* quota_node = api_call(s, 'o', NULL, &local_err, "[{a:ug, strg:1, xfer:1, pro:1}]");
  if (!quota_node)
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  mega_user_quota* q = g_new0(mega_user_quota, 1);

  q->total = s_json_get_member_int(quota_node, "mstrg", 0);
  q->used = s_json_get_member_int(quota_node, "cstrg", 0);

  g_free(quota_node);

  return q;
}

// }}}

// {{{ mega_session_ls_all

static void _ls_all(gchar* path, mega_node* n, GSList** l)
{
  *l = g_slist_prepend(*l, n);
}

// free gslist, not the data
GSList* mega_session_ls_all(mega_session* s)
{
  GSList* list = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);

  g_hash_table_foreach(s->fs_pathmap, (GHFunc)_ls_all, &list);

  return g_slist_sort(list, (GCompareFunc)strcmp);
}

// }}}
// {{{ mega_session_ls

struct _ls_data
{
  GSList* list;
  gchar* path;
  gboolean recursive;
};

static void _ls(gchar* path, mega_node* n, struct _ls_data* data)
{
  if (g_str_has_prefix(path, data->path) && (data->recursive || !strchr(path + strlen(data->path), '/')))
    data->list = g_slist_prepend(data->list, n);
}

// free gslist, not the data
GSList* mega_session_ls(mega_session* s, const gchar* path, gboolean recursive)
{
  struct _ls_data data;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);

  gchar* tmp = path_simplify(path);

  if (!strcmp(tmp, "/"))
    data.path = g_strdup("/");
  else
    data.path = g_strdup_printf("%s/", tmp);
  data.recursive = recursive;
  data.list = NULL;
  g_free(tmp);

  g_hash_table_foreach(s->fs_pathmap, (GHFunc)_ls, &data);

  g_free(data.path);
  return data.list;
}

// }}}
// {{{ mega_session_stat

mega_node* mega_session_stat(mega_session* s, const gchar* path)
{
  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);

  gchar* tmp = path_simplify(path);
  mega_node* n = g_hash_table_lookup(s->fs_pathmap, path);
  g_free(tmp);

  return n;
}

// }}}
// {{{ mega_session_get_node_chilren

GSList* mega_session_get_node_chilren(mega_session* s, mega_node* node)
{
  GSList *list = NULL, *i;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(node != NULL, NULL);
  g_return_val_if_fail(node->handle != NULL, NULL);

  for (i = s->fs_nodes; i; i = i->next)
  {
    mega_node* child = i->data;

    if (child->parent_handle && !strcmp(child->parent_handle, node->handle))
      list = g_slist_prepend(list, child);
  }

  return g_slist_reverse(list);
}

// }}}
// {{{ mega_session_mkdir

mega_node* mega_session_mkdir(mega_session* s, const gchar* path, GError** err)
{
  GError* local_err = NULL;
  mega_node* n = NULL;
  gchar* mkdir_node = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  mega_node* d = mega_session_stat(s, path);
  if (d)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory already exists: %s", path);
    return NULL;
  }

  gchar* tmp = path_simplify(path);
  gchar* parent_path = g_path_get_dirname(tmp);
  g_free(tmp);

  if (!strcmp(parent_path, "/"))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create toplevel dir: %s", path);
    g_free(parent_path);
    return NULL;
  }

  mega_node* p = mega_session_stat(s, parent_path);
  if (!p || p->type == MEGA_NODE_FILE || p->type == MEGA_NODE_INBOX)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s", parent_path);
    g_free(parent_path);
    return NULL;
  }

  if (!mega_node_is_writable(s, p))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory is not writable: %s", parent_path);
    g_free(parent_path);
    return NULL;
  }

  g_free(parent_path);

  if (p->type == MEGA_NODE_NETWORK)
  {
    // prepare contact add request
    gchar* ur_node = api_call(s, 'o', NULL, &local_err, "[{a:ur, u:%S, l:1, i:%s}]", g_path_get_basename(path), s->rid);
    if (!ur_node)
    {
      g_propagate_error(err, local_err);
      return NULL;
    }

    // parse response
    n = mega_node_parse_user(s, ur_node);
    if (!n)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      g_free(ur_node);
      return NULL;
    }

    g_free(ur_node);
  }
  else
  {
    MegaAesKey* node_key = mega_aes_key_new_generated();
    gchar* basename = g_path_get_basename(path);
    gchar* attrs = encode_node_attrs(basename);
    gchar* dir_attrs = mega_aes_key_encrypt_string_cbc(node_key, attrs);
    gchar* dir_key = mega_aes_key_get_enc_ubase64(node_key, s->master_key);
    g_free(basename);
    g_free(attrs);
    g_object_unref(node_key);

    // prepare request
    mkdir_node = api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, i:%s, n: [{h:xxxxxxxx, t:1, k:%S, a:%S}]}]", p->handle, s->rid, dir_key, dir_attrs);
    if (!mkdir_node)
    {
      g_propagate_error(err, local_err);
      goto err;
    }

    const gchar* f_arr = s_json_get_member(mkdir_node, "f");
    if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    const gchar* f_el = s_json_get_element(f_arr, 0);
    if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    n = mega_node_parse(s, f_el);
    if (!n)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    g_free(mkdir_node);
  }

  // add mkdired node to the filesystem
  s->fs_nodes = g_slist_append(s->fs_nodes, n);
  update_pathmap(s);

  return n;

err:
  g_free(mkdir_node);
  return NULL;
}

// }}}
// {{{ mega_session_rm

gboolean mega_session_rm(mega_session* s, const gchar* path, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->fs_pathmap != NULL, FALSE);
  g_return_val_if_fail(path != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_node* mn = mega_session_stat(s, path);
  if (!mn)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File not found: %s", path);
    return FALSE;
  }

  if (!mega_node_is_writable(s, mn))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File is not removable: %s", path);
    return FALSE;
  }

  if (mn->type == MEGA_NODE_FILE || mn->type == MEGA_NODE_FOLDER)
  {
    // prepare request
    gchar* rm_node = api_call(s, 'i', NULL, &local_err, "[{a:d, i:%s, n:%s}]", s->rid, mn->handle);
    if (!rm_node)
    {
      g_propagate_error(err, local_err);
      return FALSE;
    }

    g_free(rm_node);
  }
  else if (mn->type == MEGA_NODE_CONTACT)
  {
    gchar* ur_node = api_call(s, 'i', NULL, &local_err, "[{a:ur, u:%s, l:0, i:%s}]", mn->handle, s->rid);
    if (!ur_node)
    {
      g_propagate_error(err, local_err);
      return FALSE;
    }

    g_free(ur_node);
  }
  else
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't remove system dir %s", path);
    return FALSE;
  }

  // remove node from the filesystem
  s->fs_nodes = g_slist_remove(s->fs_nodes, mn);
  mega_node_free(mn);
  update_pathmap(s);

  return TRUE;
}

// }}}
// {{{ mega_session_new_node_attribute

gchar* mega_session_new_node_attribute(mega_session* s, const guchar* data, gsize len, const gchar* type, MegaAesKey* key, GError** err)
{
  GError* local_err = NULL;
  gsize pad = len % 16 ? 16 - (len % 16) : 0;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);
  g_return_val_if_fail(type != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  gchar* ufa_node = api_call(s, 'o', NULL, &local_err, "[{a:ufa, s:%i, ssl:0}]", (gint64)len + pad);
  if (!ufa_node)
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  gchar* p_url = s_json_get_member_string(ufa_node, "p");
  g_free(ufa_node);

  // encrypt
  guchar* plain = g_memdup(data, len);
  plain = g_realloc(plain, len + pad);
  memset(plain + len, 0, pad);
  guchar* cipher = g_malloc0(len + pad);
  mega_aes_key_encrypt_cbc_raw(key, plain, cipher, len + pad);
  g_free(plain);

  // upload
  MegaHttpClient* h = mega_http_client_new();
  mega_http_client_set_content_type(h, "application/octet-stream");
  GString* handle = mega_http_client_post_simple(h, p_url, cipher, len + pad, &local_err);
  g_object_unref(h);
  g_free(cipher);
  g_free(p_url);

  if (!handle)
  {
    g_propagate_prefixed_error(err, local_err, "Node attribute data upload failed: ");
    g_string_free(handle, TRUE);
    return NULL;
  }

  if (handle->len != 8)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Node attribute handle is invalid");
    g_string_free(handle, TRUE);
    return NULL;
  }

  gchar* b64_handle = mega_base64urlencode(handle->str, handle->len);
  g_string_free(handle, TRUE);
  gchar* tmp = g_strdup_printf("%s*%s", type, b64_handle);
  g_free(b64_handle);

  return tmp;
}

// }}}
// {{{ create_preview

static gint has_convert = -1;
static gint has_ffmpegthumbnailer = -1;

static gchar* create_preview(mega_session* s, const gchar* local_path, MegaAesKey* key, GError** err)
{
  gchar* handle = NULL;
#ifndef G_OS_WIN32
  GError* local_err = NULL;
  gchar *tmp1 = NULL, *tmp2 = NULL, *prg;

  if (has_ffmpegthumbnailer < 0)
  {
    prg = g_find_program_in_path("ffmpegthumbnailer");
    has_ffmpegthumbnailer = !!prg;
    g_free(prg);
  }

  if (has_convert < 0)
  {
    prg = g_find_program_in_path("convert");
    has_ffmpegthumbnailer = !!prg;
    g_free(prg);
  }

  if (has_ffmpegthumbnailer && g_regex_match_simple("\\.(mpg|mpeg|avi|mkv|flv|rm|mp4|wmv|asf|ram|mov)$", local_path, G_REGEX_CASELESS, 0))
  {
    gchar buf[50] = "/tmp/megatools.XXXXXX";
    gchar* dir = g_mkdtemp(buf);
    if (dir)
    {
      gint status = 1;
      gchar* thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
      gchar* qpath = g_shell_quote(local_path);
      gchar* tmp = g_strdup_printf("ffmpegthumbnailer -t 5 -i %s -o %s/thumb.jpg -s 128 -f -a", qpath, dir);

      if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, &local_err))
      {
        if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR))
        {
          gchar* thumb_data;
          gsize thumb_len;

          if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL))
          {
            handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0", key, &local_err);
            if (!handle)
              g_propagate_error(err, local_err);

            g_free(thumb_data);
          }

          g_unlink(thumb_path);
        }
      }
      else
      {
        g_propagate_error(err, local_err);
      }

      g_rmdir(dir);
      g_free(tmp);
      g_free(qpath);
      g_free(thumb_path);
    }
  }
  else if (has_convert && g_regex_match_simple("\\.(jpe?g|png|gif|bmp|tiff|svg|pnm|eps|ico|pdf)$", local_path, G_REGEX_CASELESS, 0))
  {
    gchar buf[50] = "/tmp/megatools.XXXXXX";
    gchar* dir = g_mkdtemp(buf);
    if (dir)
    {
      gint status = 1;
      gchar* thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
      gchar* qpath = g_shell_quote(local_path);
      gchar* tmp = g_strdup_printf("convert %s -strip -resize 128x128^ -gravity center -crop 128x128+0+0 +repage %s/thumb.jpg", qpath, dir);

      if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, NULL))
      {
        if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR))
        {
          gchar* thumb_data;
          gsize thumb_len;

          if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL))
          {
            handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0", key, &local_err);
            if (!handle)
              g_propagate_error(err, local_err);

            g_free(thumb_data);
          }

          g_unlink(thumb_path);
        }
      }
      else
      {
        g_propagate_error(err, local_err);
      }

      g_rmdir(dir);
      g_free(tmp);
      g_free(qpath);
      g_free(thumb_path);
    }
  }
  else
  {
    return NULL;
  }

  g_free(tmp1);
  g_free(tmp2);

  if (!handle && err && !*err)
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create preview");

#endif
  return handle;
}

// }}}

#if 0

static gboolean progress_generic(mega_session* s, goffset total, goffset now)
{
  init_status(s, MEGA_STATUS_PROGRESS);
  s->status_data.progress.total = total;
  s->status_data.progress.done = now;
  if (send_status(s)) 
      return FALSE;

  return TRUE;
}

static gboolean splice_with_progress(mega_session* s, GInputStream* is, GOutputStream* os, GError** err)
{
  return TRUE;
}

// {{{ mega_session_put

mega_node* mega_session_put(mega_session* s, const gchar* remote_path, const gchar* local_path, GError** err)
{
  GError* local_err = NULL;
  mega_node *node, *parent_node;
  gchar* file_name = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(remote_path != NULL, NULL);
  g_return_val_if_fail(local_path != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  // check remote filesystem, and get parent node

  node = mega_session_stat(s, remote_path);
  if (node)
  {
    if (node->type == MEGA_NODE_FILE)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", remote_path);
      return NULL;
    }
    else
    {
      // put into a dir
      parent_node = node;

      gchar* basename = g_path_get_basename(local_path);
      gchar* tmp = g_strconcat(remote_path, "/", basename, NULL);
      g_free(basename);
      node = mega_session_stat(s, tmp);
      if (node)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", tmp);
        g_free(tmp);
        return NULL;
      }
      g_free(tmp);

      if (!mega_node_is_writable(s, parent_node) || parent_node->type == MEGA_NODE_NETWORK || parent_node->type == MEGA_NODE_CONTACT)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory is not writable: %s", remote_path);
        return NULL;
      }

      file_name = g_path_get_basename(local_path);
    }
  }
  else
  {
    gchar* tmp = path_simplify(remote_path);
    gchar* parent_path = g_path_get_dirname(tmp);
    g_free(tmp);

    if (!strcmp(parent_path, "/"))
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't upload to toplevel dir: %s", remote_path);
      g_free(parent_path);
      return NULL;
    }

    parent_node = mega_session_stat(s, parent_path);
    if (!parent_node || parent_node->type == MEGA_NODE_FILE)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s", parent_path);
      g_free(parent_path);
      return NULL;
    }

    if (!mega_node_is_writable(s, parent_node) || parent_node->type == MEGA_NODE_NETWORK || parent_node->type == MEGA_NODE_CONTACT)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory is not writable: %s", parent_path);
      g_free(parent_path);
      return NULL;
    }

    file_name = g_path_get_basename(remote_path);
    g_free(parent_path);
  }

  // open local file for reading, and get file size

  GFile* file = g_file_new_for_path(local_path);
  GFileInputStream* f_is = g_file_read(file, NULL, &local_err);
  if (!f_is)
  {
    g_propagate_prefixed_error(err, local_err, "Can't read local file %s: ", local_path);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }   

  GFileInfo* info = g_file_input_stream_query_info(f_is, G_FILE_ATTRIBUTE_STANDARD_SIZE, NULL, &local_err);
  if (!info)
  {
    g_propagate_prefixed_error(err, local_err, "Can't read local file %s: ", local_path);
    g_object_unref(f_is);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }

  goffset file_size = g_file_info_get_size(info);
  g_object_unref(info);

  // ask for upload url - [{"a":"u","ssl":0,"ms":0,"s":<SIZE>,"r":0,"e":0}]
  gchar* up_node = api_call(s, 'o', NULL, &local_err, "[{a:u, ssl:0, ms:0, s:%i, r:0, e:0}]", (gint64)file_size);
  if (!up_node)
  {
    g_propagate_error(err, local_err);
    g_object_unref(f_is);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }

  gchar* p_url = s_json_get_member_string(up_node, "p");
  g_free(up_node);

  // setup encryption
  MegaAesCtrEncryptor* ctr = mega_aes_ctr_encryptor_new();
  MegaChunkedCbcMac* mac = mega_chunked_cbc_mac_new();
  MegaFileKey* file_key = mega_file_key_new();

  mega_file_key_generate(file_key);
  mega_aes_ctr_encryptor_set_key(ctr, file_key);
  mega_aes_ctr_encryptor_set_mac(ctr, mac, MEGA_AES_CTR_ENCRYPTOR_DIRECTION_ENCRYPT);

  // perform upload
  MegaHttpClient* h = mega_http_client_new();
  mega_http_client_set_content_type(h, "application/octet-stream");
  MegaHttpIOStream* h_io = mega_http_client_post(h, p_url, file_size, &local_err);
  if (!h_io)
  {
    g_propagate_prefixed_error(err, local_err, "Data upload failed: ");
    goto err0;
  }

  GInputStream* h_is = g_io_stream_get_input_stream(G_IO_STREAM(h_io));
  GOutputStream* h_os = g_io_stream_get_output_stream(G_IO_STREAM(h_io));

  if (!splice_with_progress(s, h_is, h_os, file_size, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data upload failed: ");
    goto err0;
  }

  // read handle

  GString* up_handle = http_post_stream_upload(h, p_url, file_size, (http_data_fn)put_process_data, &data, &local_err);
  g_free(p_url);
  g_object_unref(f_is);
  g_object_unref(file);

  if (!up_handle)
  {
    g_propagate_prefixed_error(err, local_err, "Data upload failed: ");
    goto err0;
  }

  // check for numeric error code
  if (up_handle->len < 10 && g_regex_match_simple("^-(\\d+)$", up_handle->str, 0, 0))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error code %s", srv_error_to_string(atoi(up_handle->str)));
    goto err0;
  }

  if (up_handle->len > 100 || !g_regex_match_simple("^[a-zA-Z0-9_+/-]{20,50}$", up_handle->str, 0, 0))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid upload handle");
    goto err0;
  }

  gchar* fa = create_preview(s, local_path, aes_key, NULL);

  gchar* attrs = encode_node_attrs(file_name);
  gchar* attrs_enc = b64_aes128_cbc_encrypt_str(attrs, aes_key);
  g_free(attrs);

  guchar meta_mac[16];
  guchar node_key[32];
  chunked_cbc_mac_finish(&data.mac, meta_mac);
  pack_node_key(node_key, aes_key, nonce, meta_mac);
  gchar* node_key_enc = b64_aes128_encrypt(node_key, 32, s->master_key);

  // prepare request
  gchar* put_node = api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, n:[{h:%s, t:0, k:%S, a:%S, fa:%s}]}]", parent_node->handle, up_handle->str, node_key_enc, attrs_enc, fa);
  if (!put_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  const gchar* f_arr = s_json_get_member(put_node, "f");
  if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  const gchar* f_el = s_json_get_element(f_arr, 0);
  if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  mega_node* nn = mega_node_parse(s, f_el);
  if (!nn)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  // add uploaded node to the filesystem
  s->fs_nodes = g_slist_append(s->fs_nodes, nn);
  update_pathmap(s);

  g_free(put_node);
  http_free(h);
  g_free(aes_key);
  g_free(nonce);
  g_string_free(up_handle, TRUE);
  return nn;

err1:
  g_free(put_node);
err0:
  http_free(h);
  g_free(aes_key);
  g_free(nonce);
  g_free(file_name);
  g_string_free(up_handle, TRUE);
  return NULL;
}

// }}}
// {{{ mega_session_get

struct _get_data
{
  mega_session* s;
  GFileOutputStream* stream;
  AES_KEY k;
  guchar iv[AES_BLOCK_SIZE];
  gint num;
  guchar ecount[AES_BLOCK_SIZE];
  chunked_cbc_mac mac;
};

static gsize get_process_data(gpointer buffer, gsize size, struct _get_data* data)
{
  gchar* out_buffer = g_malloc(size);

  AES_ctr128_encrypt(buffer, out_buffer, size, &data->k, data->iv, data->ecount, &data->num);

  chunked_cbc_mac_update(&data->mac, out_buffer, size);

  init_status(data->s, MEGA_STATUS_DATA);
  data->s->status_data.data.size = size;
  data->s->status_data.data.buf = out_buffer;
  if (send_status(data->s)) 
  {
    g_free(out_buffer);
    return 0;
  }

  if (!data->stream)
  {
    g_free(out_buffer);
    return size;
  }

  if (g_output_stream_write_all(G_OUTPUT_STREAM(data->stream), out_buffer, size, NULL, NULL, NULL))
  {
    g_free(out_buffer);
    return size;
  }

  g_free(out_buffer);
  return 0;
}

gboolean mega_session_get(mega_session* s, const gchar* local_path, const gchar* remote_path, GError** err)
{
  struct _get_data data;
  GError* local_err = NULL;
  GFile* file = NULL;
  gboolean remove_file = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->fs_pathmap != NULL, FALSE);
  g_return_val_if_fail(remote_path != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  memset(&data, 0, sizeof(data));
  data.s = s;

  mega_node* n = mega_session_stat(s, remote_path);
  if (!n)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file not found: %s", remote_path);
    return FALSE;
  }

  init_status(s, MEGA_STATUS_FILEINFO);
  s->status_data.fileinfo.name = n->name;
  s->status_data.fileinfo.size = n->size;
  if (send_status(s)) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Operation cancelled from status callback");
    return FALSE;
  }

  if (local_path)
  {
    file = g_file_new_for_path(local_path);
    if (g_file_query_exists(file, NULL))
    {
      if (g_file_query_file_type(file, 0, NULL) == G_FILE_TYPE_DIRECTORY)
      {
        GFile* child = g_file_get_child(file, n->name);
        if (g_file_query_exists(child, NULL))
        {
          g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Local file already exists: %s/%s", local_path, n->name);
          g_object_unref(file);
          g_object_unref(child);
          return FALSE;
        }
        else
        {
          g_object_unref(file);
          file = child;
        }
      }
      else
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Local file already exists: %s", local_path);
        g_object_unref(file);
        return FALSE;
      }
    }

    data.stream = g_file_create(file, 0, NULL, &local_err);
    if (!data.stream)
    {
      g_propagate_prefixed_error(err, local_err, "Can't open local file %s for writing: ", local_path);
      g_object_unref(file);
      return FALSE;
    }
  }

  remove_file = TRUE;

  // initialize decrytpion key/state
  guchar aes_key[16], meta_mac_xor[8];
  unpack_node_key(n->key, aes_key, data.iv, meta_mac_xor);
  AES_set_encrypt_key(aes_key, 128, &data.k);
  chunked_cbc_mac_init8(&data.mac, aes_key, data.iv);

  // prepare request
  gchar* get_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, n:%s}]", n->handle);

  if (!get_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  gint64 file_size = s_json_get_member_int(get_node, "s", -1);
  if (file_size < 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
    goto err0;
  }

  gchar* url = s_json_get_member_string(get_node, "g");
  if (!url)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
    goto err0;
  }

  // perform download
  http* h = http_new();
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  if (!http_post_stream_download(h, url, (http_data_fn)get_process_data, &data, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data download failed: ");
    goto err1;
  }

  if (file)
  {
    if (!g_output_stream_close(G_OUTPUT_STREAM(data.stream), NULL, &local_err))
    {
      g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
      goto err1;
    }
  }

  if (file)
    g_object_unref(data.stream);

  // check mac of the downloaded file
  guchar meta_mac_xor_calc[8];
  chunked_cbc_mac_finish8(&data.mac, meta_mac_xor_calc);
  if (memcmp(meta_mac_xor, meta_mac_xor_calc, 8) != 0) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "MAC mismatch");
    goto err1;
  }

  g_free(url);
  http_free(h);
  if (file)
    g_object_unref(file);
  g_free(get_node);

  return TRUE;

err1:
  g_free(url);
  http_free(h);
err0:
  g_free(get_node);
  if (file)
  {
    g_object_unref(data.stream);
    if (remove_file)
      g_file_delete(file, NULL, NULL);
    g_object_unref(file);
  }
  return FALSE;
}

// }}}
// {{{ mega_session_dl

struct _dl_data
{
  mega_session* s;
  GFileOutputStream* stream;
  AES_KEY k;
  guchar iv[AES_BLOCK_SIZE];
  gint num;
  guchar ecount[AES_BLOCK_SIZE];
  chunked_cbc_mac mac;
};

static gsize dl_process_data(gpointer buffer, gsize size, struct _dl_data* data)
{
  gchar* out_buffer = g_malloc(size);

  AES_ctr128_encrypt(buffer, out_buffer, size, &data->k, data->iv, data->ecount, &data->num);

  chunked_cbc_mac_update(&data->mac, out_buffer, size);

  init_status(data->s, MEGA_STATUS_DATA);
  data->s->status_data.data.size = size;
  data->s->status_data.data.buf = out_buffer;
  if (send_status(data->s)) 
  {
    g_free(out_buffer);
    return 0;
  }

  if (!data->stream)
  {
    g_free(out_buffer);
    return size;
  }

  if (g_output_stream_write_all(G_OUTPUT_STREAM(data->stream), out_buffer, size, NULL, NULL, NULL))
  {
    g_free(out_buffer);
    return size;
  }

  g_free(out_buffer);
  return 0;
}

gboolean mega_session_dl(mega_session* s, const gchar* handle, const gchar* key, const gchar* local_path, GError** err)
{
  struct _dl_data data;
  GError* local_err = NULL;
  GFile *file = NULL, *parent_dir = NULL;
  gboolean remove_file = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(handle != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  memset(&data, 0, sizeof(data));
  data.s = s;

  if (local_path)
  {
    // get dir and filename to download to
    file = g_file_new_for_path(local_path);
    if (g_file_query_exists(file, NULL))
    {
      if (g_file_query_file_type(file, 0, NULL) != G_FILE_TYPE_DIRECTORY)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", local_path);
        g_object_unref(file);
        return FALSE;
      }
      else
      {
        parent_dir = file;
        file = NULL;
      }
    }
    else
    {
      parent_dir = g_file_get_parent(file);

      if (g_file_query_file_type(parent_dir, 0, NULL) != G_FILE_TYPE_DIRECTORY)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't download file into: %s", g_file_get_path(parent_dir));
        g_object_unref(parent_dir);
        return FALSE;
      }
    }
  }

  // prepare request
  gchar* dl_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, p:%s}]", handle);
  if (!dl_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  // get file size
  gint64 file_size = s_json_get_member_int(dl_node, "s", -1);
  if (file_size < 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
    goto err0;
  }

  gchar* url = s_json_get_member_string(dl_node, "g");
  if (!url)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
    goto err0;
  }

  gchar* at = s_json_get_member_string(dl_node, "at");
  if (!at)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't get file attributes");
    goto err1;
  }

  // decode node_key
  gsize node_key_len = 0;
  guchar* node_key = base64urldecode(key, &node_key_len);
  if (!node_key || node_key_len != 32)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve file key");
    goto err2;
  }

  // initialize decrytpion key
  guchar aes_key[16], meta_mac_xor[8];
  unpack_node_key(node_key, aes_key, data.iv, meta_mac_xor);

  // decrypt attributes with aes_key
  gchar* node_name = NULL;
  if (!decrypt_node_attrs(at, aes_key, &node_name))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid key");
    goto err2;
  }

  if (!node_name)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve remote file name");
    goto err2;
  }

  init_status(s, MEGA_STATUS_FILEINFO);
  s->status_data.fileinfo.name = node_name;
  s->status_data.fileinfo.size = file_size;
  if (send_status(s)) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Operation cancelled from status callback");
    g_free(node_name);
    goto err2;
  }

  // check for invalid characters in filename
#ifdef G_OS_WIN32
  if (strpbrk(node_name, "/\\<>:\"|?*") || !strcmp(node_name, ".") || !strcmp(node_name, ".."))
#else
  if (strpbrk(node_name, "/") || !strcmp(node_name, ".") || !strcmp(node_name, "..")) 
#endif
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file name is invalid: '%s'", node_name);
    g_free(node_name);
    goto err2;
  }

  if (local_path)
  {
    if (!file)
      file = g_file_get_child(parent_dir, node_name);
  }

  g_free(node_name);

  if (local_path)
  {
    // open local file for writing
    data.stream = g_file_create(file, 0, NULL, &local_err);
    if (!data.stream)
    {
      gchar* tmp = g_file_get_path(file);
      g_propagate_prefixed_error(err, local_err, "Can't open local file %s for writing: ", tmp);
      g_free(tmp);
      goto err2;
    }
  }

  remove_file = TRUE;

  // initialize decryption and mac calculation
  AES_set_encrypt_key(aes_key, 128, &data.k);
  chunked_cbc_mac_init8(&data.mac, aes_key, data.iv);

  // perform download
  http* h = http_new();
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  if (!http_post_stream_download(h, url, (http_data_fn)dl_process_data, &data, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data download failed: ");
    goto err3;
  }

  if (data.stream)
  {
    if (!g_output_stream_close(G_OUTPUT_STREAM(data.stream), NULL, &local_err))
    {
      g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
      goto err3;
    }

    g_object_unref(data.stream);
  }

  // check mac of the downloaded file
  guchar meta_mac_xor_calc[8];
  chunked_cbc_mac_finish8(&data.mac, meta_mac_xor_calc);
  if (memcmp(meta_mac_xor, meta_mac_xor_calc, 8) != 0) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "MAC mismatch");
    goto err3;
  }

  http_free(h);
  g_free(dl_node);
  if (file)
    g_object_unref(file);
  if (parent_dir)
    g_object_unref(parent_dir);
  return TRUE;

err3:
  http_free(h);
  if (data.stream)
    g_object_unref(data.stream);
err2:
  g_free(node_key);
  g_free(at);
err1:
  g_free(url);
err0:
  g_free(dl_node);
  if (file)
  {
    if (remove_file)
      g_file_delete(file, NULL, NULL);
    g_object_unref(file);
  }
  if (parent_dir)
    g_object_unref(parent_dir);
  return FALSE;
}

// }}}

#endif

// {{{ mega_node_get_link

gchar* mega_node_get_link(mega_node* n, gboolean include_key)
{
  g_return_val_if_fail(n != NULL, NULL);

  if (n->link)
  {
    if (include_key && n->key)
    {
      gchar* key = mega_node_get_key(n);
      gchar* tmp = g_strdup_printf("https://mega.co.nz/#!%s!%s", n->link, key);
      g_free(key);
      return tmp;
    }

    return g_strdup_printf("https://mega.co.nz/#!%s", n->link);
  }

  return NULL;
}

// }}}
// {{{ mega_node_get_key

gchar* mega_node_get_key(mega_node* n)
{
  g_return_val_if_fail(n != NULL, NULL);

  if (n->key)
  {
    if (MEGA_IS_AES_KEY(n->key))
      return mega_aes_key_get_ubase64(n->key);
    else if (MEGA_IS_FILE_KEY(n->key))
      return mega_file_key_get_ubase64(MEGA_FILE_KEY(n->key));
  }

  return NULL;
}

// }}}
