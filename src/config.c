/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the app configuration utilities.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <minIni.h>
#include <unistd.h>

#include "config.h"
#include "utils/allocs.h"
#include "utils/log.h"

int load_app_config(const char *filename, struct app_config *config) {
  (void)config;
  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    log_errno("Couldn't open %s config file.\n", filename);
    return -1;
  }
  fclose(fp);

  return 0;
}

void free_app_config(struct app_config *config) {
  if (config == NULL) {
    return;
  }
}
