/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief key/value list definition
 */

#ifndef KEYVALUE_H
#define KEYVALUE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "array.h"

struct keyvalue_list {
  char *key;           /**< The attribute name (heap allocated) */
  char *value;         /**< The attribute value (heap allocated) */
  struct dl_list list; /**< List definition */
};

/**
 * @brief Frees the key/value list and all of its elements
 *
 * @param[in] kv_list The key/value list
 */
void free_keyvalue_list(struct keyvalue_list *kv_list);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_keyvalue_list                                              \
  __attribute__((malloc(free_keyvalue_list, 1))) __must_check
#else
#define __must_free_keyvalue_list __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initializes the key/value list
 *
 * @return struct keyvalue_list * initialised key/value list, NULL on failure
 */
__must_free_keyvalue_list struct keyvalue_list *init_keyvalue_list(void);

/**
 * @brief Pushes the key/value/escape elements into the list
 *
 * @param[in] kv_list The key/value list
 * @param[in] key The key attribute
 * @param[in] value The attribute value
 * @return int 0 on success, -1 on failure
 */
int push_keyvalue_list(struct keyvalue_list *kv_list, char *const key,
                       char *const value);

#endif /* KEYVALUE_H */
