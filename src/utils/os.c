/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the os functionalities.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "os.h"

void *sys_realloc_array(void *ptr, const size_t nmemb, const size_t size) {
  if (size && nmemb > (~(size_t)0) / size) {
    return NULL;
  }
  return sys_realloc(ptr, nmemb * size);
}

void *sys_memdup(const void *const src, const size_t len) {
  if (src == NULL) {
    return NULL;
  }

  void *dst = sys_malloc(len);

  if (dst == NULL) {
    return NULL;
  }

  sys_memcpy(dst, src, len);

  return dst;
}

char *sys_strndup(const char *const s, const size_t length) {
  char *dest = NULL;

  if (s != NULL) {
    dest = (char *)sys_zalloc(length + 1);
    if (dest == NULL) {
      return NULL;
    }

    strncpy(dest, s, length);
  }

  return dest;
}

char *sys_strdup(const char *const s) { return sys_strndup(s, strlen(s)); }

size_t sys_strlcpy(char *const dest, const char *const src, const size_t siz) {
  /* Copy string up to the maximum size of the dest buffer */
  const char *char_after_NUL = sys_memccpy(dest, src, '\0', siz);

  if (char_after_NUL != NULL) {
    return (size_t)(char_after_NUL - dest - 1);
  } else {
    /* Not enough room for the string; force NUL-termination */
    dest[siz - 1] = '\0';
    /* determine total src string length */
    return strlen(src);
  }
}

size_t sys_strnlen_s(const char *const str, const size_t max_len) {
  char *end = (char *)memchr(str, '\0', max_len);

  if (end == NULL)
    return max_len;

  return end - str;
}
