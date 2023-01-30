/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the os functionalities.
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>

#include "log.h"
#include "os.h"

void *sys_zalloc(size_t size) { return sys_calloc(size, 1); }

char *sys_strdup(const char *s) {
  char *dest = NULL;
  size_t len = strlen(s) + 1;

  if (s != NULL) {
    dest = (char *)sys_malloc(len);
    if (dest == NULL) {
      return NULL;
    }

    strcpy(dest, s);
  }

  return dest;
}

void *sys_memdup(const void *src, size_t len) {
  void *r = sys_malloc(len);

  if (r && src)
    sys_memcpy(r, src, len);
  return r;
}

size_t sys_strlcpy(char *dest, const char *src, size_t siz) {
  /* Copy string up to the maximum size of the dest buffer */
  const char *char_after_NUL = memccpy(dest, src, '\0', siz);

  if (char_after_NUL != NULL) {
    return (size_t)(char_after_NUL - dest - 1);
  } else {
    /* Not enough room for the string; force NUL-termination */
    dest[siz - 1] = '\0';
    /* determine total src string length */
    return strlen(src);
  }
}
