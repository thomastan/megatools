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

static gboolean opt_names;
static gboolean opt_recursive;
static gboolean opt_long;
static gboolean opt_human;
static gboolean opt_export;
static gboolean opt_header;

static GOptionEntry entries[] =
{
  { "names",         'n',   0, G_OPTION_ARG_NONE,    &opt_names,        "Print file and folder names only",            NULL },
  { "recursive",     'R',   0, G_OPTION_ARG_NONE,    &opt_recursive,    "List files and folders recursively",          NULL },
  { "long",          'l',   0, G_OPTION_ARG_NONE,    &opt_long,         "Use a long listing format",                   NULL },
  { "header",       '\0',   0, G_OPTION_ARG_NONE,    &opt_header,       "Show columns header in long listing",         NULL },
  { "human",         'h',   0, G_OPTION_ARG_NONE,    &opt_human,        "Format file sizes in human readable way",     NULL },
  { "export",        'e',   0, G_OPTION_ARG_NONE,    &opt_export,       "Show mega.co.nz download links (export)",     NULL },
  { NULL }
};

static gint compare_node(MegaNode* a, MegaNode* b)
{
  const gchar* ap = mega_node_get_path(a);
  const gchar* bp = mega_node_get_path(b);

  if (ap == NULL && bp == NULL)
    return 0;

  if (ap == NULL)
    return -1;

  if (bp == NULL)
    return 1;

  return strcmp(ap, bp);
}

int main(int ac, char* av[])
{
  MegaSession* s;
  MegaFilesystem* fs;
  GError *local_err = NULL;
  GSList *l = NULL, *i;
  gint j;

  tool_init(&ac, &av, "- list files stored at mega.co.nz", entries);

  s = tool_start_session();
  fs = mega_session_get_filesystem(s);

  // gather nodes

  if (ac == 1)
  {
    l = mega_filesystem_filter_nodes(fs, NULL, NULL);
  }
  else
  {
    for (j = 1; j < ac; j++)
      l = g_slist_concat(l, mega_filesystem_glob(fs, av[j]));

    if (opt_recursive)
    {
      for (i = l; i; i = i->next)
      {
        MegaNode* node = i->data;

        if (!mega_node_is(node, MEGA_NODE_TYPE_FILE))
          l = g_slist_concat(l, mega_node_collect_children(node));
      }
    }
  }

  l = g_slist_sort(l, (GCompareFunc)compare_node);

  // export files if requested
  
  if (opt_export && !mega_filesystem_export_nodes(fs, l, &local_err))
  {
    g_printerr("ERROR: Can't read links info from mega.co.nz: %s\n", local_err ? local_err->message : "unknown error");
    g_slist_free(l);
    g_clear_error(&local_err);
    tool_fini(s);
    return 1;
  }

  // output

  if (l && opt_long && opt_header && !opt_export)
  {
    g_print("===================================================================================\n");
    g_print("%-11s %-11s %-1s %13s %-19s %s\n", "Handle", "Owner", "T", "Size", "Mod. Date", opt_names ? "Filename" : "Path");
    g_print("===================================================================================\n");
  }

  for (i = l; i; i = i->next)
  {
    MegaNode* node = i->data;

    if (opt_export)
    {
      gchar* link = mega_node_get_public_url(node, TRUE);
      if (link)
        g_print("%73s ", link);

      g_free(link);
    }

    if (opt_long)
    {
      gint64 ts, size;
      gint type;
      gchar* owner_handle;
      g_object_get(node, "timestamp", &ts, "size", &size, "type", &type, "owner-handle", &owner_handle, NULL);

      GDateTime* dt = g_date_time_new_from_unix_local(ts);
      gchar* time_str = g_date_time_format(dt, "%Y-%m-%d %H:%M:%S");
      g_date_time_unref(dt);

      gchar* size_str;
      if (opt_human)
        size_str = size > 0 ? g_format_size_full(size, G_FORMAT_SIZE_IEC_UNITS) : g_strdup("-");
      else
        size_str = size > 0 ? g_strdup_printf("%" G_GUINT64_FORMAT, size) : g_strdup("-");

      g_print("%-11s %-11s %d %13s %19s %s\n",
        mega_node_get_handle(node), 
        owner_handle ? owner_handle : "",
        type,
        size_str,
        ts > 0 ? time_str : "", 
        opt_names ? mega_node_get_name(node) : mega_node_get_path(node)
      );

      g_free(time_str);
      g_free(size_str);
    }
    else
      g_print("%s\n", opt_names ? mega_node_get_name(node) : mega_node_get_path(node));
  }

  g_slist_free_full(l, (GDestroyNotify)g_object_unref);
  tool_fini(s);
  return 0;
}
