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
 * MegaChunkedCbcMac:
 *
 * Object for calculating Meta-MAC from CBC-MACs of data chunks. To calculate
 * meta mac, you need IV, AES key, and data.
 *
 * Calculation is done in three steps:
 *
 *   - setup
 *   - update(s)
 *   - finish
 */

#include <string.h>
#include "mega-chunked-cbc-mac.h"

struct _MegaChunkedCbcMacPrivate
{
  MegaAesKey* key;
  gsize chunk_idx;
  guint64 next_boundary;
  guint64 position;
  guchar chunk_mac_iv[16];
  guchar chunk_mac[16];
  guchar meta_mac[16];
  gboolean finished;
};

static guint64 get_chunk_size(gsize idx)
{
  return (idx < 8 ? idx + 1 : 8) * 1024 * 128;
}

G_GNUC_UNUSED static gsize get_chunk_off(gint idx)
{
  gsize p = 0;
  gint i = 0;

  for (i = 0; i < idx; i++)
    p += get_chunk_size(i);

  return p;
}

static void close_chunk(MegaChunkedCbcMacPrivate* priv)
{
  gint i;
  guchar tmp[16];

  for (i = 0; i < 16; i++)
    priv->meta_mac[i] ^= priv->chunk_mac[i];

  mega_aes_key_encrypt_raw(priv->key, priv->meta_mac, tmp, 16);
  memcpy(priv->meta_mac, tmp, 16);

  memcpy(priv->chunk_mac, priv->chunk_mac_iv, 16);
  priv->next_boundary += get_chunk_size(++priv->chunk_idx);
}

/**
 * mega_chunked_cbc_mac_new:
 *
 * Create new #MegaChunkedCbcMac object.
 *
 * Returns: #MegaChunkedCbcMac object.
 */
MegaChunkedCbcMac* mega_chunked_cbc_mac_new(void)
{
  return g_object_new(MEGA_TYPE_CHUNKED_CBC_MAC, NULL);
}

/**
 * mega_chunked_cbc_mac_setup:
 * @mac: a #MegaChunkedCbcMac
 * @key: AES key to be used for calculation.
 * @iv: (element-type guint8) (array fixed-size=8) (transfer none): Initialization vector.
 *
 * Initialize MAC calculator.
 */
void mega_chunked_cbc_mac_setup(MegaChunkedCbcMac* mac, MegaAesKey* key, guchar* iv)
{
  MegaChunkedCbcMacPrivate* priv;

  g_return_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac));
  g_return_if_fail(key != NULL);
  g_return_if_fail(iv != NULL);

  priv = mac->priv;

  g_clear_object(&priv->key);

  priv = mac->priv;
  priv->key = g_object_ref(key);
  priv->chunk_idx = 0;
  priv->next_boundary = get_chunk_size(priv->chunk_idx);
  priv->position = 0;
  memcpy(priv->chunk_mac_iv, iv, 16);
  memcpy(priv->chunk_mac, iv, 16);
  memset(priv->meta_mac, 0, 16);
}

/**
 * mega_chunked_cbc_mac_update:
 * @mac: a #MegaChunkedCbcMac
 * @data: (element-type guint8) (array length=len) (transfer none): Plaintext * data.
 * @len: Length of the data buffer.
 *
 * Feed data to the MAC calculator.
 */
void mega_chunked_cbc_mac_update(MegaChunkedCbcMac* mac, const guchar* data, gsize len)
{
  MegaChunkedCbcMacPrivate* priv;
  gsize i;

  g_return_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac));
  g_return_if_fail(!mac->priv->finished);
  g_return_if_fail(data != NULL);

  priv = mac->priv;

  for (i = 0; i < len; i++)
  {
    priv->chunk_mac[priv->position % 16] ^= data[i];
    priv->position++;

    if (G_UNLIKELY((priv->position % 16) == 0))
    {
      guchar tmp[16];
      mega_aes_key_encrypt_raw(priv->key, priv->chunk_mac, tmp, 16);
      memcpy(priv->chunk_mac, tmp, 16);
    }

    // add chunk mac to the chunk macs list if we are at the chunk boundary
    if (G_UNLIKELY(priv->position == priv->next_boundary)) 
      close_chunk(priv);
  }
}

/**
 * mega_chunked_cbc_mac_finish:
 * @mac: a #MegaChunkedCbcMac
 * @meta_mac: (out caller-allocates) (element-type guint8) (array fixed-size=16): Meta MAC.
 *
 * Finish MAC calculation and return Meta-MAC.
 */
void mega_chunked_cbc_mac_finish(MegaChunkedCbcMac* mac, guchar* meta_mac)
{
  MegaChunkedCbcMacPrivate* priv;

  g_return_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac));
  g_return_if_fail(meta_mac != NULL);

  priv = mac->priv;

  if (priv->finished)
  {
    memcpy(meta_mac, priv->meta_mac, 16);
    return;
  }

  priv->finished = TRUE;

  // finish buffer if necessary
  if (priv->position % 16)
  {
    while (priv->position % 16)
    {
      priv->chunk_mac[priv->position % 16] ^= 0;
      priv->position++;
    }

    guchar tmp[16];
    mega_aes_key_encrypt_raw(priv->key, priv->chunk_mac, tmp, 16);
    memcpy(priv->chunk_mac, tmp, 16);
  }

  // if there last chunk is unfinished, finish it
  if (priv->position > (priv->next_boundary - get_chunk_size(priv->chunk_idx)))
    close_chunk(priv);

  memcpy(meta_mac, priv->meta_mac, 16);
}

// {{{ GObject type setup

G_DEFINE_TYPE(MegaChunkedCbcMac, mega_chunked_cbc_mac, G_TYPE_OBJECT);

static void mega_chunked_cbc_mac_init(MegaChunkedCbcMac *mac)
{
  mac->priv = G_TYPE_INSTANCE_GET_PRIVATE(mac, MEGA_TYPE_CHUNKED_CBC_MAC, MegaChunkedCbcMacPrivate);
}

static void mega_chunked_cbc_mac_finalize(GObject *object)
{
  MegaChunkedCbcMac *mac = MEGA_CHUNKED_CBC_MAC(object);
  
  g_clear_object(&mac->priv->key);

  G_OBJECT_CLASS(mega_chunked_cbc_mac_parent_class)->finalize(object);
}

static void mega_chunked_cbc_mac_class_init(MegaChunkedCbcMacClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);

  gobject_class->finalize = mega_chunked_cbc_mac_finalize;

  g_type_class_add_private(klass, sizeof(MegaChunkedCbcMacPrivate));
}

// }}}
