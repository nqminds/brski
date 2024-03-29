/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2005, Jouni Malinen <j@w1.fi>, 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the serialization utilities.
 */
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#include "../utils/os.h"

#include "serialize.h"

static const uint8_t base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *concatenate_keyvalue(const char *key, const char *value,
                           const bool separator) {
  size_t key_size = strlen(key);
  size_t value_length = strlen(value);

  /* key + ":" + value + ","*/
  size_t length = key_size + value_length + 2;
  if (separator) {
    length++;
  }

  char *concat = sys_malloc(length);

  if (concat == NULL) {
    log_errno("sys_malloc");
    return NULL;
  }

  if (separator) {
    sprintf(concat, "%s:%s,", key, value);
  } else {
    sprintf(concat, "%s:%s", key, value);
  }

  return concat;
}

char *serialize_keyvalue2json(const struct keyvalue_list *kv_list) {
  if (kv_list == NULL) {
    log_error("kv_list param is NULL");
    return NULL;
  }

  unsigned int count = dl_list_len(&kv_list->list), idx = 0;

  if (!count) {
    log_error("kv_list is empty");
    return NULL;
  }

  char *json = sys_zalloc(2);
  if (json == NULL) {
    log_errno("sys_malloc");
    return NULL;
  }

  strcat(json, "{");

  struct keyvalue_list *el = NULL;
  size_t length = strlen(json) + 1;

  dl_list_for_each(el, &kv_list->list, struct keyvalue_list, list) {
    char *concat = concatenate_keyvalue(el->key, el->value, (idx < count - 1));
    if (concat == NULL) {
      log_error("concatenate_keyvalue fail");
      sys_free(json);
      return NULL;
    }

    length += strlen(concat);

    char *tmp = NULL;
    if ((tmp = sys_realloc_array(json, sizeof(char), length)) == NULL) {
      log_errno("sys_realloc_array");
      sys_free(concat);
      sys_free(json);
      return NULL;
    }

    strcat(tmp, concat);
    json = tmp;

    sys_free(concat);
    idx++;
  }

  length++;

  char *tmp = NULL;
  if ((tmp = sys_realloc_array(json, sizeof(char), length)) == NULL) {
    log_errno("sys_realloc_array");
    sys_free(json);
    return NULL;
  }

  strcat(tmp, "}");

  return tmp;
}

static uint8_t *base64_gen_encode(const uint8_t *src, const size_t len,
                                  size_t *out_len, const uint8_t *table,
                                  const int add_pad) {
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

  olen++; /* nul termination */

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

static ssize_t base64_gen_decode(const uint8_t *src, const size_t len,
                                 const uint8_t *table, uint8_t **out) {
  uint8_t dtable[256], *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;
  size_t extra_pad;

  *out = NULL;

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
    return -1;
  }
  extra_pad = (4 - count % 4) % 4;

  olen = (count + extra_pad) / 4 * 3;
  if ((*out = (uint8_t *)sys_malloc(olen)) == NULL) {
    log_errno("sys_malloc");
    return -1;
  }
  pos = *out;

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
          sys_free(*out);
          return -1;
        }
        break;
      }
    }
  }

  return (ssize_t)(pos - *out);
}

ssize_t serialize_array2base64str(const uint8_t *src, const size_t length,
                                  uint8_t **out) {
  size_t out_len;

  *out = NULL;

  uint8_t *encoded = base64_gen_encode(src, length, &out_len, base64_table, 1);
  if (encoded == NULL) {
    log_error("base64_gen_encode fail");
    return -1;
  }
  *out = encoded;
  return (ssize_t)out_len;
}

ssize_t serialize_base64str2array(const uint8_t *src, const size_t length,
                                  uint8_t **out) {
  ssize_t out_len = base64_gen_decode(src, length, base64_table, out);
  if (out_len < 0) {
    log_error("base64_gen_decode fail");
    return -1;
  }

  return out_len;
}

char *serialize_bool2str(const bool value) {
  char buf[6];
  if (value) {
    sprintf(buf, "true");
  } else {
    sprintf(buf, "false");
  }

  return sys_strdup(buf);
}

int serialize_str2bool(const char *str, const size_t length) {
  if (str == NULL) {
    log_error("str param is NULL");
    return -1;
  }

  if (!length) {
    log_error("length param is NULL");
    return -1;
  }

  char buf[6];

  if (length > 5) {
    return -1;
  }

  if (strncmp(str, "0", 1) == 0 && length == 1) {
    return 0;
  } else if (strncmp(str, "1", 1) == 0 && length == 1) {
    return 1;
  } else {
    size_t idx = 0;
    while (idx < length) {
      buf[idx] = tolower(str[idx]);
      idx++;
    }
    buf[idx] = '\0';

    if (strcmp(buf, "false") == 0) {
      return 0;
    } else if (strcmp(buf, "true") == 0) {
      return 1;
    } else {
      return -1;
    }
  }
}

char *serialize_time2str(const struct tm *value) {
  char buf[sizeof("9999-12-31T24:59:59Z") + 1];

  if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", value) == 0) {
    log_error("strftime fail");
    return NULL;
  }

  return sys_strdup(buf);
}

int serialize_str2time(const char *str, const struct tm *tm) {
  if (str == NULL) {
    log_error("str param is NULL");
    return -1;
  }

  if (tm == NULL) {
    log_error("tm param is NULL");
    return -1;
  }

  sys_memset((void *)tm, 0, sizeof(struct tm));

  if (strptime(str, "%Y-%m-%dT%H:%M:%SZ", (struct tm *)tm) == NULL) {
    log_error("strptime fail");
    return -1;
  }

  return 0;
}

char *serialize_localtime(void) {
  struct tm value = {0};

  if (get_localtime(&value) < 0) {
    log_error("get_localtime fail");
    return NULL;
  }

  char *str = NULL;
  if ((str = serialize_time2str(&value)) == NULL) {
    log_error("serialize_time2str fail");
    return NULL;
  }

  return str;
}

char *serialize_escapestr(const char *str) {
  if (str == NULL) {
    log_error("str param is NULL");
    return NULL;
  }

  size_t length = strlen(str);
  /* ""(2 chars) + \0 (1 char) = 3 chars*/
  char *serialized = sys_malloc(length + 3);

  if (serialized == NULL) {
    log_errno("sys_malloc");
    return NULL;
  }
  sprintf(serialized, "\"%s\"", str);

  return serialized;
}
