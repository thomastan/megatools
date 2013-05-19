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

#ifndef __TOOLS_H__
#define __TOOLS_H__

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>
#include <mega/mega.h>
#include "sjson.h"

#ifdef G_OS_WIN32
#define ESC_CLREOL ""
#define ESC_WHITE ""
#define ESC_GREEN ""
#define ESC_GRAY ""
#define ESC_NORMAL ""
#else
#define ESC_CLREOL "\x1b[0K"
#define ESC_WHITE "\x1b[37;1m"
#define ESC_GREEN "\x1b[32;1m"
#define ESC_GRAY "\x1b[30;1m"
#define ESC_NORMAL "\x1b[0m"
#endif

#define DEBUG_API   0x0001
#define DEBUG_FS    0x0002
#define DEBUG_CACHE 0x0004

extern guint tool_debug;
extern gboolean tool_allow_unknown_options;

void            tool_init_bare        (gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries);
void            tool_init             (gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries);
MegaSession*    tool_start_session    (void);
void            tool_fini             (MegaSession* s);

gchar*          tool_prompt           (gboolean echo, const gchar* format, ...);
gboolean        tool_is_interactive   (void);

gboolean        is_email_valid        (const gchar* email);
gboolean        is_user_handle_valid  (const gchar* handle);

#endif
