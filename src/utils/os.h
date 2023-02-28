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

#ifndef __must_check
#if defined __has_attribute
#if __has_attribute(__warn_unused_result__)
/**
 * If used before a function, tells compilers that the result of the function
 * should be used and not ignored.
 *
 * @see
 * https://clang.llvm.org/docs/AttributeReference.html#nodiscard-warn-unused-result
 */
#define __must_check __attribute__((__warn_unused_result__))
#else
#define __must_check
#endif /* __has_attribute(__warn_unused_result__) */
#else
#define __must_check
#endif /* defined __has_attribute */
#endif /* __has_attribute */

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang, since
                   // __attribute__((malloc)) accepts no args
/**
 * Declares that the attributed function must be free()-ed with `__must_free()`.
 *
 * Expects that this function returns a pointer that must be `free()`-ed with
 * `free()`.
 *
 * Please be aware that `__attribute((malloc))` instead does something
 * completely different and should **NOT** be used. It tells the compiler about
 * pointer aliasing, which does not apply to functions like `realloc()`, and
 * so are not part of this macro.
 *
 * @see
 * https://gcc.gnu.org/onlinedocs/gcc-11.1.0/gcc/Common-Function-Attributes.html#index-malloc-function-attribute
 */
#define __must_free __attribute__((malloc(free, 1))) __must_check
#else
#define __must_free __must_check
#endif /* __GNUC__ >= 11 */

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
