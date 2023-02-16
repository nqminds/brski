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
};

#define DL_LIST_HEAD_INIT(l)                                                   \
  { &(l), &(l) }

static inline void dl_list_init(struct dl_list *list) {
  list->next = list;
  list->prev = list;
}

static inline void dl_list_add(struct dl_list *list, struct dl_list *item) {
  item->next = list->next;
  item->prev = list;
  list->next->prev = item;
  list->next = item;
}

static inline void dl_list_add_tail(struct dl_list *list,
                                    struct dl_list *item) {
  dl_list_add(list->prev, item);
}

static inline void dl_list_del(struct dl_list *item) {
  item->next->prev = item->prev;
  item->prev->next = item->next;
  item->next = NULL;
  item->prev = NULL;
}

static inline int dl_list_empty(const struct dl_list *list) {
  return list->next == list;
}

static inline unsigned int dl_list_len(const struct dl_list *list) {
  struct dl_list *item;
  int count = 0;
  for (item = list->next; item != list; item = item->next)
    count++;
  return count;
}

#ifndef offsetof
#define offsetof(type, member) ((long)&((type *)0)->member)
#endif

#define dl_list_entry(item, type, member)                                      \
  ((type *)((char *)item - offsetof(type, member)))

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

#define dl_list_for_each_reverse(item, list, type, member)                     \
  for (item = dl_list_entry((list)->prev, type, member);                       \
       &item->member != (list);                                                \
       item = dl_list_entry(item->member.prev, type, member))

#define DEFINE_DL_LIST(name) struct dl_list name = {&(name), &(name)}

struct keyvalue_list {
  char *key;           /**< The attribute name (heap allocated) */
  char *value;         /**< The attribute value (heap allocated) */
  struct dl_list list; /**< List definition */
};

/**
 * @brief Initializes the key/value list
 *
 * @return struct keyvalue_list * initialised key/value list, NULL on failure
 */
struct keyvalue_list *init_keyvalue_list(void);

/**
 * @brief Frees the key/value list and all of its elements
 *
 * @param[in] kv_list The key/value list
 */
void free_keyvalue_list(struct keyvalue_list *kv_list);

/**
 * @brief Pushes the key/value/escape elements into the list
 *
 * @param[in] kv_list The key/value list
 * @param[in] key The key attribute
 * @param[in] value The attribute value
 * @return int 0 on success, -1 on failure
 */
int push_keyvalue_list(struct keyvalue_list *kv_list, char *key, char *value);

struct buffer_list {
  uint8_t *buf;        /**< The buffer (heap allocated) */
  size_t length;       /**< The buffer length (heap allocated) */
  int flags;           /**< The generic buffer flags */
  struct dl_list list; /**< List definition */
};

/**
 * @brief Initializes the buffer list
 *
 * @return struct buffer_list * initialised buffer list, NULL on failure
 */
struct buffer_list *init_buffer_list(void);

/**
 * @brief Frees the buffer list and all of its elements
 *
 * @param[in] buf_list The buffer list
 */
void free_buffer_list(struct buffer_list *buf_list);

/**
 * @brief Pushes the buffer pointer into the list
 * and assigns the flags
 *
 * @param[in] buf_list The buffer list
 * @param[in] buf The buffer pointer
 * @param[in] length The buffer length
 * @param[in] flags The buffer flags
 * @return int 0 on success, -1 on failure
 */
int push_buffer_list(struct buffer_list *buf_list, uint8_t *buf, size_t length,
                     int flags);

#endif /* LIST_H */
