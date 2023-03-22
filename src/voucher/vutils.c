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

#include "vutils.h"

static void dl_list_init(struct dl_list *list, void *el) {
  list->next = list;
  list->prev = list;
  list->el = el;
}

static void dl_list_add(struct dl_list *list, struct dl_list *item, void *el) {
  item->next = list->next;
  item->prev = list;
  list->next->prev = item;
  list->next = item;
  list->next->el = el;
}

static void dl_list_add_tail(struct dl_list *list, struct dl_list *item,
                             void *el) {
  dl_list_add(list->prev, item, el);
}

static void dl_list_del(struct dl_list *item) {
  item->next->prev = item->prev;
  item->prev->next = item->next;
  item->next = NULL;
  item->prev = NULL;
}

int dl_list_empty(const struct dl_list *list) { return list->next == list; }

unsigned int dl_list_len(const struct dl_list *list) {
  struct dl_list *item;
  int count = 0;
  for (item = list->next; item != list; item = item->next)
    count++;
  return count;
}

struct keyvalue_list *init_keyvalue_list(void) {
  struct keyvalue_list *kv_list = NULL;

  if ((kv_list = sys_zalloc(sizeof(struct keyvalue_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&kv_list->list, (void *)kv_list);

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

int push_keyvalue_list(struct keyvalue_list *kv_list, char *const key,
                       char *const value) {
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

  struct keyvalue_list *el = sys_zalloc(sizeof(struct keyvalue_list));

  if (el == NULL) {
    log_error("init_keyvalue_list fail");
    return -1;
  }

  el->key = key;
  el->value = value;

  dl_list_add_tail(&kv_list->list, &el->list, (void *)el);

  return 0;
}

struct buffer_list *init_buffer_list(void) {
  struct buffer_list *buf_list = NULL;

  if ((buf_list = sys_zalloc(sizeof(struct buffer_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&buf_list->list, (void *)buf_list);

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

int push_buffer_list(struct buffer_list *buf_list, uint8_t *const buf,
                     const size_t length, const int flags) {
  if (buf_list == NULL) {
    log_error("buf_list param is empty");
    return -1;
  }

  if (buf == NULL) {
    log_error("buf param is empty");
    return -1;
  }

  struct buffer_list *el = sys_zalloc(sizeof(struct buffer_list));

  if (el == NULL) {
    log_error("init_buffer_list fail");
    return -1;
  }

  el->buf = buf;
  el->length = length;
  el->flags = flags;

  dl_list_add_tail(&buf_list->list, &el->list, (void *)el);

  return 0;
}

struct ptr_list *init_ptr_list(void) {
  struct ptr_list *ptr_list = NULL;

  if ((ptr_list = sys_zalloc(sizeof(struct ptr_list))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&ptr_list->list, (void *)ptr_list);

  return ptr_list;
}

static void free_ptr_list_el(struct ptr_list *el, const ptr_free_fn cb) {
  if (el != NULL) {
    if (el->ptr != NULL && cb != NULL) {
      cb(el->ptr, el->flags);
    }
    dl_list_del(&el->list);
    sys_free(el);
  }
}

void free_ptr_list(struct ptr_list *ptr_list, const ptr_free_fn cb) {
  struct ptr_list *el;

  if (ptr_list == NULL) {
    return;
  }

  while ((el = dl_list_first(&ptr_list->list, struct ptr_list, list)) != NULL) {
    free_ptr_list_el(el, cb);
  }

  free_ptr_list_el(ptr_list, cb);
}

int push_ptr_list(struct ptr_list *ptr_list, void *const ptr, const int flags) {
  if (ptr_list == NULL) {
    log_error("ptr_list param is empty");
    return -1;
  }

  if (ptr == NULL) {
    log_error("ptr param is empty");
    return -1;
  }

  struct ptr_list *el = sys_zalloc(sizeof(struct ptr_list));

  if (el == NULL) {
    log_error("init_ptr_list fail");
    return -1;
  }

  el->ptr = ptr;
  el->flags = flags;

  dl_list_add_tail(&ptr_list->list, &el->list, (void *)el);

  return 0;
}

int copy_binary_array(struct VoucherBinaryArray *const dst,
                      const struct VoucherBinaryArray *src) {
  if (dst == NULL) {
    log_error("dst param is NULL");
    return -1;
  }

  if (src == NULL) {
    log_error("src param is NULL");
    return -1;
  }
  dst->length = 0;
  if ((dst->array = sys_memdup((uint8_t *)src->array, src->length)) == NULL) {
    log_errno("sys_memdup");
    return -1;
  }
  dst->length = src->length;

  return 0;
}

int compare_binary_array(const struct VoucherBinaryArray *src,
                         const struct VoucherBinaryArray *dst) {
  if (src == NULL) {
    log_error("src param is NULL");
    return -1;
  }

  if (dst == NULL) {
    log_error("dst param is NULL");
    return -1;
  }

  if (dst->length != src->length) {
    return 0;
  }

  if (sys_memcmp(dst->array, src->array, src->length) != 0) {
    return 0;
  };

  return 1;
}

void free_binary_array_content(struct VoucherBinaryArray *arr) {
  if (arr != NULL) {
    if (arr->array != NULL) {
      sys_free(arr->array);
      arr->array = NULL;
    }
    arr->length = 0;
  }
}

void free_binary_array(struct VoucherBinaryArray *arr) {
  if (arr != NULL) {
    free_binary_array_content(arr);
    sys_free(arr);
  }
}

