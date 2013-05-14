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
 * MegaHttpInputStream:
 *
 * Stream for reading HTTP response body.
 */

#include "mega-http-input-stream.h"
#include "mega-http-client.h"

struct _MegaHttpInputStreamPrivate
{
  MegaHttpClient* client;
};

// {{{ GObject property and signal enums

enum MegaHttpInputStreamProp
{
  PROP_0,
  PROP_CLIENT,
  N_PROPERTIES
};

enum MegaHttpInputStreamSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_http_input_stream_new:
 *
 * Create new #MegaHttpInputStream object.
 *
 * Returns: #MegaHttpInputStream object.
 */
MegaHttpInputStream* mega_http_input_stream_new(MegaHttpClient* client)
{
  return g_object_new(MEGA_TYPE_HTTP_INPUT_STREAM, "client", client, NULL);
}

static gssize stream_read(GInputStream *stream, void *buffer, gsize count, GCancellable *cancellable, GError **error)
{
  MegaHttpInputStream *http_input_stream = MEGA_HTTP_INPUT_STREAM(stream);

  return mega_http_client_read(http_input_stream->priv->client, buffer, count, cancellable, error);
}

/**
 * mega_http_input_stream_get_length:
 * @http_input_stream: a #MegaHttpInputStream
 *
 * Get length of the response body.
 *
 * Returns: Length of he response or -1 if it can't be retrieved.
 */
gssize mega_http_input_stream_get_length(MegaHttpInputStream* http_input_stream, GCancellable* cancellable, GError** err)
{
  g_return_val_if_fail(MEGA_IS_HTTP_INPUT_STREAM(http_input_stream), -1);

  return mega_http_client_get_response_length(http_input_stream->priv->client, cancellable, err);
}

// {{{ GObject type setup

static void mega_http_input_stream_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaHttpInputStream *http_input_stream = MEGA_HTTP_INPUT_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      http_input_stream->priv->client = g_value_dup_object(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_http_input_stream_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaHttpInputStream *http_input_stream = MEGA_HTTP_INPUT_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      g_value_set_object(value, http_input_stream->priv->client);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaHttpInputStream, mega_http_input_stream, G_TYPE_INPUT_STREAM);

static void mega_http_input_stream_init(MegaHttpInputStream *http_input_stream)
{
  http_input_stream->priv = G_TYPE_INSTANCE_GET_PRIVATE(http_input_stream, MEGA_TYPE_HTTP_INPUT_STREAM, MegaHttpInputStreamPrivate);
}

static void mega_http_input_stream_finalize(GObject *object)
{
  MegaHttpInputStream *http_input_stream = MEGA_HTTP_INPUT_STREAM(object);

  g_clear_object(&http_input_stream->priv->client);

  G_OBJECT_CLASS(mega_http_input_stream_parent_class)->finalize(object);
}

static void mega_http_input_stream_class_init(MegaHttpInputStreamClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_http_input_stream_set_property;
  gobject_class->get_property = mega_http_input_stream_get_property;

  gobject_class->finalize = mega_http_input_stream_finalize;

  g_type_class_add_private(klass, sizeof(MegaHttpInputStreamPrivate));

  G_INPUT_STREAM_CLASS(klass)->read_fn = stream_read;

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "client",
    /* nick    */ "Client",
    /* blurb   */ "Set/get client",
    /* is_type */ MEGA_TYPE_HTTP_CLIENT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY
  );

  g_object_class_install_property(gobject_class, PROP_CLIENT, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
