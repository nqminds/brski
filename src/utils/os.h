/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the os functionalities.
 */

#ifndef OS_H
#define OS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(s) (sizeof(s) / sizeof(s[0]))
#endif

/**
 * @brief Allocate and zero memory
 *
 * Caller is responsible for freeing the returned buffer with sys_free().
 *
 * @param size Number of bytes to allocate
 * @return void* Pointer to allocated and zeroed memory or %NULL on failure
 */
void *sys_zalloc(const size_t size);

/**
 * sys_memdup - Allocate duplicate of passed memory chunk
 *
 * This function allocates a memory block like sys_malloc() would, and
 * copies the given source buffer into it.
 *
 * @param src Source buffer to duplicate
 * @param len Length of source buffer
 * @return void* %NULL if allocation failed, copy of src buffer otherwise
 */
void *sys_memdup(const void *const src, const size_t len);

#ifndef sys_zalloc
#define sys_zalloc(s) sys_zalloc(s)
#endif

// void *sys_malloc(size_t size);
// void sys_free(void* ptr);

#ifndef sys_malloc
#define sys_malloc(s) malloc(s)
#endif

#ifndef sys_realloc
#define sys_realloc(p, s) realloc(p, s)
#endif

#ifndef sys_calloc
#define sys_calloc(nm, s) calloc(nm, s)
#endif

#ifndef sys_free
#define sys_free(p) free(p)
#endif

#ifndef sys_memcpy
#define sys_memcpy(d, s, n) memcpy(d, s, n)
#endif
#ifndef sys_memccpy
#define sys_memccpy(d, s, c, n) memccpy(d, s, c, n)
#endif
#ifndef sys_memmove
#define sys_memmove(d, s, n) memmove(d, s, n)
#endif
#ifndef sys_memset
#define sys_memset(s, c, n) memset(s, c, n)
#endif
#ifndef sys_memcmp
#define sys_memcmp(s1, s2, n) memcmp(s1, s2, n)
#endif

/**
 * @brief Reallocates the given area of a memory array (uses realloc).
 * 
 * @param ptr Pointer to the memory area to be reallocated
 * @param nmemb The size of each array element
 * @param size Size of the array to reallocate
 * @return void* the pointer to the beginning of newly allocated memory array,
 * NULL on failure.
 */
void *sys_realloc_array(void *ptr, const size_t nmemb, const size_t size);

/**
 * @brief Allocate duplicate of passed memory chunk
 *
 * This function allocates a memory block like os_malloc() would, and
 * copies the given source buffer into it.
 *
 * @param src Source buffer to duplicate
 * @param len Length of source buffer
 * @return void* %NULL if allocation failed, copy of src buffer otherwise
 */
void *sys_memdup(const void *const src, const size_t len);

/**
 * @brief Returns a pointer to a new string which is a duplicate of the string s
 * for a given string length
 *
 * @param s The input string
 * @param length The length of the string not including the '\0' character
 * @return char* The dublicate string pointer, NULL on error
 */
char *sys_strndup(const char *const s, const size_t length);

/**
 * @brief Returns a pointer to a new string which is a duplicate of the string s
 *
 * @param s The input string
 * @return char* The dublicate string pointer, NULL on error
 */
char *sys_strdup(const char *const s);

/**
 * @brief Copy a string with size bound and NUL-termination
 *
 * This function matches in behavior with the strlcpy(3) function in OpenBSD.
 *
 * @param dest Destination string
 * @param src Source string
 * @param siz Size of the target buffer
 * @return size_t Total length of the target string (length of src) (not
 * including NUL-termination)
 */
size_t sys_strlcpy(char *const dest, const char *const src, const size_t siz);

/**
 * @brief Returns the size of string with a give max length
 *
 * @param str The string pointer
 * @param max_len The string max length
 * @return size_t Total length of the string
 */
size_t sys_strnlen_s(const char *const str, const size_t max_len);
#endif /* OS_H */
