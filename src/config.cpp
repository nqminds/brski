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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <minIni.h>
#include <unistd.h>

#include "config.h"

extern "C" {
#include "utils/log.h"
#include "utils/os.h"
}

#include "http/http.h"

int load_server_config(const char *filename, struct http_config *hconf) {
  try {
    char *key = new char[INI_BUFFERSIZE];

    ini_gets("server", "bindAddress", "0.0.0.0", key, INI_BUFFERSIZE, filename);
    sys_strlcpy(hconf->bindAddress, key, MAX_WEB_PATH_LEN);
    delete [] key;

    hconf->port = (unsigned int)ini_getl("server", "port", 0, filename);
  } catch(...) {
    log_error("failed to allocate key");
    return -1;
  }

  return 0;
}


int load_brski_config(const char *filename, struct brski_config *config) {
  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    log_errno("Couldn't open %s config file.\n", filename);
    return -1;
  }
  fclose(fp);

  if (load_server_config(filename, &config->hconf) < 0) {
    log_error("load_server_config fail");
    return -1;
  }

  return 0;
}
