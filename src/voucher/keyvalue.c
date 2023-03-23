/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief key/value list implementation
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../utils/log.h"
#include "../utils/os.h"

#include "array.h"
#include "keyvalue.h"

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

  el->key = sys_strdup(key);
  if (el->key == NULL) {
    log_errno("sys_strdup");
    free_keyvalue_list_el(el);
    return -1;
  }

  el->value = sys_strdup(value);
  if (el->value == NULL) {
    log_errno("sys_strdup");
    free_keyvalue_list_el(el);
    return -1;
  }

  dl_list_add_tail(&kv_list->list, &el->list, (void *)el);

  return 0;
}
