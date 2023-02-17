/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * Copyright (c) 2009-2019, Jouni Malinen <j@w1.fi> and Alexandru Mereacre
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief Doubly-linked list and key/value list definition
 */
#include <stdint.h>
#include <ctype.h>

#include "../utils/os.h"

#include "list.h"

struct keyvalue_list *init_keyvalue_list(void) {
  struct keyvalue_list *kv_list = NULL;

  if ((kv_list = sys_zalloc(sizeof(struct keyvalue_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&kv_list->list);

  return kv_list;
}

static void free_keyvalue_list_el(struct keyvalue_list *el) {
  if (el != NULL) {
    if (el->key != NULL) {
      sys_free(el->key);
    }
    if (el->value != NULL) {
      sys_free(el->value);
    }
    dl_list_del(&el->list);
    sys_free(el);
  }
}

void free_keyvalue_list(struct keyvalue_list *kv_list) {
  struct keyvalue_list *el;

  if (kv_list == NULL) {
    return;
  }

  while ((el = dl_list_first(&kv_list->list, struct keyvalue_list, list)) !=
         NULL) {
    free_keyvalue_list_el(el);
  }

  free_keyvalue_list_el(kv_list);
}

int push_keyvalue_list(struct keyvalue_list *kv_list, char *key, char *value) {
  if (kv_list == NULL) {
    log_error("kv_list param is empty");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is empty");
    return -1;
  }

  if (value == NULL) {
    log_error("value param is empty");
    return -1;
  }

  struct keyvalue_list *el = init_keyvalue_list();

  if (el == NULL) {
    log_error("init_keyvalue_list fail");
    return -1;
  }

  el->key = key;
  el->value = value;

  dl_list_add_tail(&kv_list->list, &el->list);

  return 0;
}

struct buffer_list *init_buffer_list(void) {
  struct buffer_list *buf_list = NULL;

  if ((buf_list = sys_zalloc(sizeof(struct buffer_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&buf_list->list);

  return buf_list;
}

static void free_buffer_list_el(struct buffer_list *el) {
  if (el != NULL) {
    if (el->buf != NULL) {
      sys_free(el->buf);
    }
    dl_list_del(&el->list);
    sys_free(el);
  }
}

void free_buffer_list(struct buffer_list *buf_list) {
  struct buffer_list *el;

  if (buf_list == NULL) {
    return;
  }

  while ((el = dl_list_first(&buf_list->list, struct buffer_list, list)) !=
         NULL) {
    free_buffer_list_el(el);
  }

  free_buffer_list_el(buf_list);
}

int push_buffer_list(struct buffer_list *buf_list, uint8_t *buf, size_t length,
                     int flags) {
  if (buf_list == NULL) {
    log_error("buf_list param is empty");
    return -1;
  }

  if (buf == NULL) {
    log_error("buf param is empty");
    return -1;
  }

  struct buffer_list *el = init_buffer_list();

  if (el == NULL) {
    log_error("init_buffer_list fail");
    return -1;
  }

  el->buf = buf;
  el->length = length;
  el->flags = flags;

  dl_list_add_tail(&buf_list->list, &el->list);

  return 0;
}

struct ptr_list *init_ptr_list(void) {
  struct ptr_list *ptr_list = NULL;

  if ((ptr_list = sys_zalloc(sizeof(struct ptr_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&ptr_list->list);

  return ptr_list;
}

static void free_ptr_list_el(struct ptr_list *el, ptr_free_fn cb) {
  if (el != NULL) {
    if (el->ptr != NULL && cb != NULL) {
      cb(el->ptr, el->flags);
    }
    dl_list_del(&el->list);
    sys_free(el);
  }
}

void free_ptr_list(struct ptr_list *ptr_list, ptr_free_fn cb) {
  struct ptr_list *el;

  if (ptr_list == NULL) {
    return;
  }

  while ((el = dl_list_first(&ptr_list->list, struct ptr_list, list)) !=
         NULL) {
    free_ptr_list_el(el, cb);
  }

  free_ptr_list_el(ptr_list, cb);
}

int push_ptr_list(struct ptr_list *ptr_list, void *ptr, int flags) {
  if (ptr_list == NULL) {
    log_error("ptr_list param is empty");
    return -1;
  }

  if (ptr == NULL) {
    log_error("ptr param is empty");
    return -1;
  }

  struct ptr_list *el = init_ptr_list();

  if (el == NULL) {
    log_error("init_ptr_list fail");
    return -1;
  }

  el->ptr = ptr;
  el->flags = flags;

  dl_list_add_tail(&ptr_list->list, &el->list);

  return 0;
}
