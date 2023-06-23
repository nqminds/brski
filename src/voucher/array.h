/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * Copyright (c) 2009-2019, Jouni Malinen <j@w1.fi> and Alexandru Mereacre
 * SPDX-License-Identifier: BSD licence
 * @version hostapd-2.10
 * @brief Binary array(list) definition
 */

#ifndef ARRAY_H
#define ARRAY_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __must_check
#if defined __has_attribute
#if __has_attribute(__warn_unused_result__)
#define __must_check __attribute__((__warn_unused_result__))
#else
#define __must_check
#endif /* __has_attribute(__warn_unused_result__) */
#else
#define __must_check
#endif /* defined __has_attribute */
#endif /* __has_attribute */

#ifndef __must_sys_free
#if __GNUC__ >= 11
#define __must_sys_free __attribute__((malloc(free, 1))) __must_check
#else
#define __must_sys_free __must_check
#endif /* __GNUC__ >= 11 */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * struct dl_list - Doubly-linked list
 */
struct dl_list {
  struct dl_list *next;
  struct dl_list *prev;
  void *el;
};

static inline void dl_list_add_tail(struct dl_list *list, struct dl_list *item,
                                    void *element) {
  struct dl_list *prev = list->prev;

  item->next = prev->next;
  item->prev = prev;
  prev->next->prev = item;
  prev->next = item;
  prev->next->el = element;
}

static inline unsigned int dl_list_len(const struct dl_list *list) {
  struct dl_list *item;
  int count = 0;
  for (item = list->next; item != list; item = item->next)
    count++;
  return count;
}

#define dl_list_init(list, element)                                            \
  do {                                                                         \
    (list)->next = list;                                                       \
    (list)->prev = list;                                                       \
    (list)->el = element;                                                      \
  } while (0)

#define dl_list_del(item)                                                      \
  do {                                                                         \
    (item)->next->prev = (item)->prev;                                         \
    (item)->prev->next = (item)->next;                                         \
    (item)->next = NULL;                                                       \
    (item)->prev = NULL;                                                       \
  } while (0)

#define dl_list_empty(list) ((list)->next == list)

#define dl_list_entry(item, type, member) ((type *)((void *)item->el))

#define dl_list_first(list, type, member)                                      \
  (dl_list_empty((list)) ? NULL : dl_list_entry((list)->next, type, member))

#define dl_list_last(list, type, member)                                       \
  (dl_list_empty((list)) ? NULL : dl_list_entry((list)->prev, type, member))

#define dl_list_for_each(item, list, type, member)                             \
  for (item = dl_list_entry((list)->next, type, member);                       \
       &item->member != (list);                                                \
       item = dl_list_entry(item->member.next, type, member))

#define dl_list_for_each_safe(item, n, list, type, member)                     \
  for (item = dl_list_entry((list)->next, type, member),                       \
      n = dl_list_entry(item->member.next, type, member);                      \
       &item->member != (list);                                                \
       item = n, n = dl_list_entry(n->member.next, type, member))

struct BinaryArrayList {
  uint8_t *arr;        /**< The binary array (heap allocated) */
  size_t length;       /**< The binary array length */
  int flags;           /**< The generic buffer flags */
  struct dl_list list; /**< The list definition */
};

/**
 * @brief Frees the binary array list and all of its elements
 *
 * @param[in] arr_list The binary array list
 */
void free_array_list(struct BinaryArrayList *arr_list);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_array_list                                                 \
  __attribute__((malloc(free_array_list, 1))) __must_check
#else
#define __must_free_array_list __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initializes the binary array list parameters
 *
 * @return struct BinaryArrayList * initialised binary array list, NULL on
 * failure
 */
__must_free_array_list struct BinaryArrayList *init_array_list(void);

/**
 * @brief Pushes a heap allocated binary array into the list
 * and assigns the flags
 *
 * @param[in] arr_list The binary array list
 * @param[in] arr The binary array pointer
 * @param[in] length The binary array length
 * @param[in] flags The binary array flags
 * @return int 0 on success, -1 on failure
 */
int push_array_list(struct BinaryArrayList *arr_list, uint8_t *const arr,
                    const size_t length, const int flags);

struct BinaryArray {
  uint8_t *array;
  size_t length;
};

/**
 * @brief Copies a binary arrays to a destination
 *
 * @param[in] dst The destination binary array
 * @param[in] src The source binary array
 * @return int 0 on success, -1 on failure
 */
int copy_binary_array(struct BinaryArray *const dst,
                      const struct BinaryArray *src);

/**
 * @brief Frees a binary array content
 *
 * @param[in] arr The binary array
 */
void free_binary_array_content(struct BinaryArray *arr);

/**
 * @brief Frees a binary array structure and its content
 *
 * @param[in] arr The binary array
 */
void free_binary_array(struct BinaryArray *arr);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_binary_array                                               \
  __attribute__((malloc(free_binary_array, 1))) __must_check
#else
#define __must_free_binary_array __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initializes a new empty binary array.
 *
 * @return Initialized binary array that must be deallocated with
 * free_binary_array(), or `NULL` on failure.
 */
__must_free_binary_array struct BinaryArray *init_binary_array(void);

/**
 * @brief Compare two binary arrays
 *
 * @param[in] src The source binary array
 * @param[in] dst The destination binary array
 * @return int 1 if array equal, 0 otherwise, -1 on failure
 */
int compare_binary_array(const struct BinaryArray *src,
                         const struct BinaryArray *dst);

#ifdef __cplusplus
}
#endif

#endif /* ARRAY_H */
