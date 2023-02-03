/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2005, Jouni Malinen <j@w1.fi>, 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the serialization utilities.
 */
#include <stdint.h>

#include "../utils/os.h"

static const uint8_t base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint8_t *base64_gen_encode(const uint8_t *src, size_t len,
                                        size_t *out_len,
                                        const uint8_t *table,
                                        int add_pad) {
  uint8_t *out, *pos;
  const uint8_t *end, *in;
  size_t olen;

  if (len >= SIZE_MAX / 4) {
    log_error("Array exceeds max size");
    return NULL;
  }

  olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */

  if (add_pad) {
    olen += olen / 72; /* line feeds */
  }

  olen++;              /* nul termination */

  if (olen < len) {
    log_error("Integer overflow");
    return NULL;
  }

  out = (uint8_t *)sys_malloc(olen);
  if (out == NULL) {
    log_errno("sys_malloc");
    return NULL;
  }

  end = src + len;
  in = src;
  pos = out;
  while (end - in >= 3) {
    *pos++ = table[(in[0] >> 2) & 0x3f];
    *pos++ = table[(((in[0] & 0x03) << 4) | (in[1] >> 4)) & 0x3f];
    *pos++ = table[(((in[1] & 0x0f) << 2) | (in[2] >> 6)) & 0x3f];
    *pos++ = table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = table[(in[0] >> 2) & 0x3f];
    if (end - in == 1) {
      *pos++ = table[((in[0] & 0x03) << 4) & 0x3f];
      if (add_pad) {
        *pos++ = '=';
      }
    } else {
      *pos++ = table[(((in[0] & 0x03) << 4) | (in[1] >> 4)) & 0x3f];
      *pos++ = table[((in[1] & 0x0f) << 2) & 0x3f];
    }
    if (add_pad) {
      *pos++ = '=';
    }
  }

  *pos = '\0';
  if (out_len) {
    *out_len = pos - out;
  }
  return out;
}

static uint8_t *base64_gen_decode(const uint8_t *src, size_t len,
                                        size_t *out_len,
                                        const uint8_t *table) {
  uint8_t dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;
  size_t extra_pad;

  *out_len = 0;

  sys_memset(dtable, 0x80, 256);
  for (i = 0; i < sizeof(base64_table) - 1; i++) {
    dtable[table[i]] = (uint8_t)i;
  }
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80) {
      count++;
    }
  }

  if (count == 0) {
    log_error("Invalid encoding");
    return NULL;
  }
  extra_pad = (4 - count % 4) % 4;

  olen = (count + extra_pad) / 4 * 3;
  pos = out = (uint8_t *)sys_malloc(olen);
  if (out == NULL) {
    log_errno("sys_malloc");
    return NULL;
  }

  count = 0;
  for (i = 0; i < len + extra_pad; i++) {
    uint8_t val;

    if (i >= len) {
      val = '=';
    } else {
      val = src[i];
    }

    tmp = dtable[val];
    if (tmp == 0x80) {
      continue;
    }

    if (val == '=') {
      pad++;
    }

    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
        if (pad == 1) {
          pos--;
        } else if (pad == 2) {
          pos -= 2;
        } else {
          log_error("Invalid padding");
          sys_free(out);
          return NULL;
        }
        break;
      }
    }
  }

  *out_len = pos - out;
  return out;
}

uint8_t *serialize_array2base64str(const uint8_t *src, size_t len,
                             size_t *out_len) {
  return base64_gen_encode(src, len, out_len, base64_table, 1);
}

uint8_t *serialize_base64str2array(const uint8_t *src, size_t length,
                             size_t *out_length) {
  return base64_gen_decode(src, length, out_length, base64_table);
}

char *serialize_bool2str(bool value) {
  char buf[6];
  if (value) {
    sprintf(buf, "true");
  } else {
    sprintf(buf, "false");
  }

  return sys_strdup(buf);
}