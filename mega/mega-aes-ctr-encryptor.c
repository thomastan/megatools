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
 * MegaAesCtrEncryptor:
 *
 * Stream converter that can be used for CTR encryption and decryption with MAC
 * calculation.
 *
 * To use it you need to create #GConverterInputStream or #GConverterOutputStream.
 */

#include <string.h>
#include "mega-aes-ctr-encryptor.h"

struct _MegaAesCtrEncryptorPrivate
{
  MegaFileKey* key;
  MegaChunkedCbcMac* mac;
  guint64 position;
  MegaAesCtrEncryptorDirection direction;
};

/**
 * mega_aes_ctr_encryptor_new:
 *
 * Create new #MegaAesCtrEncryptor object.
 *
 * Returns: #MegaAesCtrEncryptor object.
 */
MegaAesCtrEncryptor* mega_aes_ctr_encryptor_new(void)
{
  return g_object_new(MEGA_TYPE_AES_CTR_ENCRYPTOR, NULL);
}

static void reset(GConverter *converter)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(converter);

  // Not implemented
}

static GConverterResult convert(GConverter *converter, const void *inbuf, gsize inbuf_size, void *outbuf, gsize outbuf_size, GConverterFlags flags, gsize *bytes_read, gsize *bytes_written, GError **error)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(converter);
  MegaAesCtrEncryptorPrivate* priv = encryptor->priv;
  guchar nonce[8];

  if (!priv->key || !mega_aes_key_is_loaded(MEGA_AES_KEY(priv->key)))
  {
    g_set_error(error, 1, 0, "No key is set for AES-CTR decryption/encryption!");
    return G_CONVERTER_ERROR;
  }

  if (outbuf_size < inbuf_size) 
  {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "No space");
    return G_CONVERTER_ERROR;
  }

  *bytes_written = *bytes_read = 0;
  mega_file_key_get_nonce(priv->key, nonce);

  // if input is not aligned, align it
  if (inbuf_size > 0 && priv->position % 16 != 0)
  {
    gsize offset = priv->position % 16;;
    gsize to_align = MIN(inbuf_size, 16 - offset);
    guchar align_buf[16];

    if (priv->direction == MEGA_AES_CTR_ENCRYPTOR_DIRECTION_ENCRYPT && priv->mac)
      mega_chunked_cbc_mac_update(priv->mac, align_buf + offset, to_align);

    memcpy(align_buf + offset, inbuf, to_align);
    mega_aes_key_encrypt_ctr(MEGA_AES_KEY(priv->key), nonce, priv->position / 16, align_buf, align_buf, 16);
    memcpy(outbuf, align_buf + offset, to_align);

    if (priv->direction == MEGA_AES_CTR_ENCRYPTOR_DIRECTION_DECRYPT)
      mega_chunked_cbc_mac_update(priv->mac, outbuf, to_align);

    *bytes_written = *bytes_read = to_align;
    priv->position += to_align;
    outbuf += to_align; inbuf += to_align;
    inbuf_size -= to_align; outbuf_size -= to_align;
  }

  // we are aligned, and there are more data on the input
  if (inbuf_size > 0)
  {
    if (priv->direction == MEGA_AES_CTR_ENCRYPTOR_DIRECTION_ENCRYPT && priv->mac)
      mega_chunked_cbc_mac_update(priv->mac, inbuf, inbuf_size);

    mega_aes_key_encrypt_ctr(MEGA_AES_KEY(priv->key), nonce, priv->position / 16, inbuf, outbuf, inbuf_size);

    if (priv->direction == MEGA_AES_CTR_ENCRYPTOR_DIRECTION_DECRYPT && priv->mac)
      mega_chunked_cbc_mac_update(priv->mac, outbuf, inbuf_size);

    *bytes_written = *bytes_read = *bytes_read + inbuf_size;
    priv->position += inbuf_size;
  }

  if (flags & G_CONVERTER_INPUT_AT_END)
    return G_CONVERTER_FINISHED;

  if (flags & G_CONVERTER_FLUSH)
    return G_CONVERTER_FLUSHED;

  return G_CONVERTER_CONVERTED;
}

/**
 * mega_aes_ctr_encryptor_set_key:
 * @aes_ctr_encryptor: a #MegaAesCtrEncryptor
 * @key: a #MegaFileKey that will be used for encryption/decryption.
 *
 * Set file key that will be used for encryption/decryption.
 */
void mega_aes_ctr_encryptor_set_key(MegaAesCtrEncryptor* aes_ctr_encryptor, MegaFileKey* key)
{
  g_return_if_fail(MEGA_IS_AES_CTR_ENCRYPTOR(aes_ctr_encryptor));
  g_return_if_fail(MEGA_IS_FILE_KEY(key));

  g_clear_object(&aes_ctr_encryptor->priv->key);
  aes_ctr_encryptor->priv->key = g_object_ref(key);
}

/**
 * mega_aes_ctr_encryptor_set_position:
 * @aes_ctr_encryptor: a #MegaAesCtrEncryptor
 * @position: Starting position for encryption/decryption.
 *
 * When decrypting the stream, decryptor needs to know position within the file
 * that we are starting from, so that AES-CTR counter is set correctly.
 */
void mega_aes_ctr_encryptor_set_position(MegaAesCtrEncryptor* aes_ctr_encryptor, guint64 position)
{
  g_return_if_fail(MEGA_IS_AES_CTR_ENCRYPTOR(aes_ctr_encryptor));

  aes_ctr_encryptor->priv->position = position;
}

/**
 * mega_aes_ctr_encryptor_set_mac:
 * @aes_ctr_encryptor: a #MegaAesCtrEncryptor
 * @mac: a #MegaChunkedCbcMac calculator
 *
 * Add calculator for mac's.
 */
void mega_aes_ctr_encryptor_set_mac(MegaAesCtrEncryptor* aes_ctr_encryptor, MegaChunkedCbcMac* mac, MegaAesCtrEncryptorDirection dir)
{
  MegaAesCtrEncryptorPrivate* priv;
  guchar mac_iv[16];

  g_return_if_fail(MEGA_IS_AES_CTR_ENCRYPTOR(aes_ctr_encryptor));
  g_return_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac));
  g_return_if_fail(aes_ctr_encryptor->priv->key != NULL);

  priv = aes_ctr_encryptor->priv;
  priv->direction = dir;

  g_clear_object(&priv->mac);
  priv->mac = g_object_ref(mac);

  // mac iv is nonce + nonce

  mega_file_key_get_nonce(priv->key, mac_iv);
  mega_file_key_get_nonce(priv->key, mac_iv + 8);

  mega_chunked_cbc_mac_setup(mac, MEGA_AES_KEY(priv->key), mac_iv);
}

// {{{ GObject type setup

static void mega_aes_ctr_encryptor_converter_iface_init(GConverterIface *iface)
{
  iface->convert = convert;
  iface->reset = reset;
}

G_DEFINE_TYPE_WITH_CODE(MegaAesCtrEncryptor, mega_aes_ctr_encryptor, G_TYPE_OBJECT,
  G_IMPLEMENT_INTERFACE(G_TYPE_CONVERTER, mega_aes_ctr_encryptor_converter_iface_init)
);

static void mega_aes_ctr_encryptor_init(MegaAesCtrEncryptor *aes_ctr_encryptor)
{
  aes_ctr_encryptor->priv = G_TYPE_INSTANCE_GET_PRIVATE(aes_ctr_encryptor, MEGA_TYPE_AES_CTR_ENCRYPTOR, MegaAesCtrEncryptorPrivate);
}

static void mega_aes_ctr_encryptor_dispose(GObject *object)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(object);
  MegaAesCtrEncryptorPrivate* priv = encryptor->priv;

  g_clear_object(&priv->mac);

  G_OBJECT_CLASS(mega_aes_ctr_encryptor_parent_class)->dispose(object);
}

static void mega_aes_ctr_encryptor_finalize(GObject *object)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(object);
  MegaAesCtrEncryptorPrivate* priv = encryptor->priv;

  g_clear_object(&priv->key);

  G_OBJECT_CLASS(mega_aes_ctr_encryptor_parent_class)->finalize(object);
}

static void mega_aes_ctr_encryptor_class_init(MegaAesCtrEncryptorClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);

  gobject_class->dispose = mega_aes_ctr_encryptor_dispose;
  gobject_class->finalize = mega_aes_ctr_encryptor_finalize;

  g_type_class_add_private(klass, sizeof(MegaAesCtrEncryptorPrivate));
}

// }}}
