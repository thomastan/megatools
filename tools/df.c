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

static gboolean opt_human;
static gboolean opt_mb;
static gboolean opt_gb;
static gboolean opt_total;
static gboolean opt_free;
static gboolean opt_used;

static GOptionEntry entries[] =
{
  { "human",         'h',   0, G_OPTION_ARG_NONE,    &opt_human,         "Use human readable formatting",    NULL       },
  { "mb",           '\0',   0, G_OPTION_ARG_NONE,    &opt_mb,            "Show numbers in MiB",              NULL       },
  { "gb",           '\0',   0, G_OPTION_ARG_NONE,    &opt_gb,            "Show numbers in GiB",              NULL       },
  { "total",        '\0',   0, G_OPTION_ARG_NONE,    &opt_total,         "Show only total available space",  NULL       },
  { "used",         '\0',   0, G_OPTION_ARG_NONE,    &opt_used,          "Show only used space",             NULL       },
  { "free",         '\0',   0, G_OPTION_ARG_NONE,    &opt_free,          "Show only available free space",   NULL       },
  { NULL }
};

static gchar* format_size(gint64 size)
{
  if (opt_human)
    return g_format_size_full(size, G_FORMAT_SIZE_IEC_UNITS);
  else if (opt_mb)
    size /= 1024 * 1024;
  else if (opt_gb)
    size /= 1024 * 1024 * 1024;

  return g_strdup_printf("%" G_GINT64_FORMAT, size);
}

static void print_line(const gchar* label, const gchar* str)
{
  g_print("%-24s%s\n", label, str);
}

static void print_json(const gchar* json, const gchar* label, const gchar* path)
{
  const gchar* el = s_json_path(json, path);
  if (el)
  {
    gchar* str = s_json_get_string(el);
    if (str)
      print_line(label, str);
    g_free(str);
  }
}

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  MegaSession* s;

  tool_init(&ac, &av, "- display mega.co.nz storage information", entries);

  if (opt_total || opt_free || opt_used)
  {
    gint opts_used = 0;
    opts_used += opt_total ? 1 : 0;
    opts_used += opt_free ? 1 : 0;
    opts_used += opt_used ? 1 : 0;

    if (opt_used > 1)
    {
      g_printerr("ERROR: Options conflict, you should use either --total, --used, or --free.\n");
      return 1;
    }
  }

  if (opt_human || opt_mb || opt_gb)
  {
    gint opts_used = 0;
    opts_used += opt_human ? 1 : 0;
    opts_used += opt_mb ? 1 : 0;
    opts_used += opt_gb ? 1 : 0;

    if (opt_used > 1)
    {
      g_printerr("ERROR: Options conflict, you should use either --human, --mb, or --gb.\n");
      return 1;
    }
  }

  s = tool_start_session();

  gchar* info = mega_session_get_info(s, &local_err);
  if (!info)
  {
    g_printerr("ERROR: Can't determine disk usage: %s\n", local_err ? local_err->message : "unknown error");
    g_clear_error(&local_err);
    tool_fini(s);
    return 1;
  }

  gint64 total = s_json_get_member_int(info, "total_storage", -1);
  gint64 used = s_json_get_member_int(info, "used_storage", -1);
  gint64 free = total >= used ? total - used : 0;

  if (opt_total)
    g_print("%s\n", format_size(total));
  else if (opt_used)
    g_print("%s\n", format_size(used));
  else if (opt_free)
    g_print("%s\n", format_size(free));
  else
  {
    print_json(info, "User handle:",         ".user!s");
    print_json(info, "User email:",          ".email!s");
    print_json(info, "User name:",           ".name!s");
    print_json(info, "User type:",           ".user_type!s");
    print_json(info, "Subscpription type:",  ".subscription_type!s");
    print_json(info, "Subscpription cycle:", ".subscription_cycle!s");
    print_json(info, "Next payment:",        ".subscription_next_payment!s");
    print_json(info, "Subscribed until:",    ".subscription_until!s");
    print_line(      "Total:",               format_size(total));
    print_line(      "Used:",                format_size(used));
    print_line(      "Free:",                format_size(free));
  }

  g_free(info);
  tool_fini(s);
  return 0;
}
