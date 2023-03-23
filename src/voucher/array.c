/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * Copyright (c) 2009-2019, Jouni Malinen <j@w1.fi> and Alexandru Mereacre
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief Binary array(list) implementation
 */
#include <stdint.h>
#include <ctype.h>

#include "../utils/os.h"

#include "array.h"

struct BinaryArrayList *init_array_list(void) {
  struct BinaryArrayList *arr_list = NULL;

  if ((arr_list = sys_zalloc(sizeof(struct BinaryArrayList))) == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

  dl_list_init(&arr_list->list, (void *)arr_list);

  return arr_list;
}

static void free_array_list_el(struct BinaryArrayList *el) {
  if (el != NULL) {
    if (el->arr != NULL) {
      sys_free(el->arr);
    }
    dl_list_del(&el->list);
    sys_free(el);
  }
}

void free_array_list(struct BinaryArrayList *arr_list) {
  struct BinaryArrayList *el;

  if (arr_list == NULL) {
    return;
  }

  while ((el = dl_list_first(&arr_list->list, struct BinaryArrayList, list)) !=
         NULL) {
    free_array_list_el(el);
  }

  free_array_list_el(arr_list);
}

int push_array_list(struct BinaryArrayList *arr_list, uint8_t *const arr,
                    const size_t length, const int flags) {
  if (arr_list == NULL) {
    log_error("arr_list param is empty");
    return -1;
  }

  if (arr == NULL) {
    log_error("arr param is empty");
    return -1;
  }

  struct BinaryArrayList *el = sys_zalloc(sizeof(struct BinaryArrayList));

  if (el == NULL) {
    log_error("init_array_list fail");
    return -1;
  }

  if ((el->arr = sys_memdup(arr, length)) == NULL) {
    log_errno("sys_memdup");
    free_array_list_el(el);
    return -1;
  }

  el->length = length;
  el->flags = flags;

  dl_list_add_tail(&arr_list->list, &el->list, (void *)el);

  return 0;
}

int copy_binary_array(struct BinaryArray *const dst,
                      const struct BinaryArray *src) {
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

int compare_binary_array(const struct BinaryArray *src,
                         const struct BinaryArray *dst) {
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

void free_binary_array_content(struct BinaryArray *arr) {
  if (arr != NULL) {
    if (arr->array != NULL) {
      sys_free(arr->array);
      arr->array = NULL;
    }
    arr->length = 0;
  }
}

void free_binary_array(struct BinaryArray *arr) {
  if (arr != NULL) {
    free_binary_array_content(arr);
    sys_free(arr);
  }
}
