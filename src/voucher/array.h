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

#ifndef LIST_H
#define LIST_H

#include <stddef.h>

/**
 * struct dl_list - Doubly-linked list
 */
struct dl_list {
  struct dl_list *next;
  struct dl_list *prev;
  void *el;
};

int dl_list_empty(const struct dl_list *list);

unsigned int dl_list_len(const struct dl_list *list);

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

#define DEFINE_DL_LIST(name) struct dl_list name = {&(name), &(name)}

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

struct ptr_list {
  void *ptr;           /**< The pointer (points to heap memory) */
  int flags;           /**< The generic pointer flags */
  struct dl_list list; /**< List definition */
};

typedef void (*ptr_free_fn)(void *ptr, const int flag);

/**
 * @brief Frees the ptr list and all of its elements
 * using a a user supplied callback function
 *
 * @param[in] ptr_list The ptr list
 * @param[in] cb The user supplied callback functio to free the ptr element
 */
void free_ptr_list(struct ptr_list *ptr_list, const ptr_free_fn cb);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_ptr_list                                                   \
  __attribute__((malloc(free_ptr_list, 1))) __must_check
#else
#define __must_free_ptr_list __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initializes the ptr list
 *
 * @return struct ptr_list * initialised ptr list, NULL on failure
 */
__must_free_ptr_list struct ptr_list *init_ptr_list(void);

/**
 * @brief Pushes a pointer into the list and assigns the flags
 *
 * @param[in] ptr_list The ptr list
 * @param[in] ptr The ptr value
 * @param[in] flags The ptr flags
 * @return int 0 on success, -1 on failure
 */
int push_ptr_list(struct ptr_list *ptr_list, void *const ptr, const int flags);

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
#define __must_free_array_list                                                \
  __attribute__((malloc(free_array_list, 1))) __must_check
#else
#define __must_free_array_list __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initializes the binary array list parameters
 * 
 * @return struct BinaryArrayList * initialised binary array list, NULL on failure
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

struct VoucherBinaryArray {
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
int copy_binary_array(struct VoucherBinaryArray *const dst,
                      const struct VoucherBinaryArray *src);

/**
 * @brief Frees a binary array content
 *
 * @param[in] arr The binary array
 */
void free_binary_array_content(struct VoucherBinaryArray *arr);

/**
 * @brief Frees a binary array structure and its content
 *
 * @param[in] arr The binary array
 */
void free_binary_array(struct VoucherBinaryArray *arr);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_binary_array                                               \
  __attribute__((malloc(free_binary_array, 1))) __must_check
#else
#define __must_free_binary_array __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Compare two binary arrays
 *
 * @param[in] src The source binary array
 * @param[in] dst The destination binary array
 * @return int 1 if array equal, 0 otherwise, -1 on failure
 */
int compare_binary_array(const struct VoucherBinaryArray *src,
                         const struct VoucherBinaryArray *dst);

#endif /* LIST_H */
