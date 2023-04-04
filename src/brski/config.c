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
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "../utils/log.h"
#include "../utils/os.h"
#include "../voucher/array.h"

#include "pledge/pledge_config.h"

#define CREATED_ON_SIZE sizeof("9999-12-31T24:59:59Z") + 1
#define MAX_CONFIG_VALUE_SIZE 2048

int load_config_value_list(const char *section, const char *key,
                           const char *filename,
                           struct BinaryArrayList **value_list) {
  *value_list = NULL;
  int idx = 0;

  char *store = NULL;
  if ((store = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    return -1;
  }

  if ((*value_list = init_array_list()) == NULL) {
    log_error("init_array_list fail");
    sys_free(store);
    return -1;
  }

  while (ini_getkey(section, idx++, store, MAX_CONFIG_VALUE_SIZE, filename) >
         0) {
    char *value = NULL;
    if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
      log_errno("sys_zalloc");
      sys_free(store);
      free_array_list(*value_list);
      return -1;
    }

    ini_gets(section, store, "", value, INI_BUFFERSIZE, filename);

    if (strcmp(store, key) == 0 && strlen(value)) {
      if (push_array_list(*value_list, (uint8_t *const)value, strlen(value) + 1,
                          0) < 0) {
        sys_free(value);
        sys_free(store);
        free_array_list(*value_list);
        return -1;
      }
    }

    sys_free(value);
  }

  sys_free(store);
  return 0;
}

void free_registrar_config_content(struct registrar_config *rconf) {
  if (rconf != NULL) {
    if (rconf->bind_address != NULL) {
      sys_free(rconf->bind_address);
    }

    if (rconf->tls_cert_path != NULL) {
      sys_free(rconf->tls_cert_path);
    }

    if (rconf->tls_key_path != NULL) {
      sys_free(rconf->tls_key_path);
    }
  }
}

int load_registrar_config(const char *filename,
                          struct registrar_config *const rconf) {
  char *value = NULL;

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_registrar_config_content(rconf);
    return -1;
  }

  ini_gets("registrar", "bindAddress", "0.0.0.0", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  rconf->bind_address = value;
  if (!strlen(rconf->bind_address)) {
    rconf->bind_address = NULL;
    sys_free(value);
  }

  rconf->port = (unsigned int)ini_getl("registrar", "port", 0, filename);

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_registrar_config_content(rconf);
    return -1;
  }

  ini_gets("registrar", "tlsCertPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  rconf->tls_cert_path = value;
  if (!strlen(rconf->tls_cert_path)) {
    rconf->tls_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_registrar_config_content(rconf);
    return -1;
  }

  ini_gets("registrar", "tlsKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  rconf->tls_key_path = value;
  if (!strlen(rconf->tls_key_path)) {
    rconf->tls_key_path = NULL;
    sys_free(value);
  }

  return 0;
}

void free_pledge_config_content(struct pledge_config *const pconf) {
  if (pconf != NULL) {
    if (pconf->created_on != NULL) {
      sys_free(pconf->created_on);
    }

    if (pconf->serial_number != NULL) {
      sys_free(pconf->serial_number);
    }

    if (pconf->nonce != NULL) {
      sys_free(pconf->nonce);
    }

    if (pconf->sign_cert_path != NULL) {
      sys_free(pconf->sign_cert_path);
    }

    if (pconf->sign_key_path != NULL) {
      sys_free(pconf->sign_key_path);
    }

    free_array_list(pconf->additional_cert_paths);
  }
}

int load_pledge_config(const char *filename,
                       struct pledge_config *const pconf) {
  char *value = NULL;

  if ((value = sys_zalloc(CREATED_ON_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "createdOn", "", value, CREATED_ON_SIZE, filename);
  pconf->created_on = value;
  if (!strlen(pconf->created_on)) {
    pconf->created_on = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "serialNumber", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  pconf->serial_number = value;
  if (!strlen(pconf->serial_number)) {
    pconf->serial_number = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "nonce", "", value, MAX_CONFIG_VALUE_SIZE, filename);
  pconf->nonce = value;
  if (!strlen(pconf->nonce)) {
    pconf->nonce = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "cmsSignCertPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  pconf->sign_cert_path = value;
  if (!strlen(pconf->sign_cert_path)) {
    pconf->sign_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "cmsSignKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  pconf->sign_key_path = value;
  if (!strlen(pconf->sign_key_path)) {
    pconf->sign_key_path = NULL;
    sys_free(value);
  }

  if (load_config_value_list("pledge", "cmsAdditionalCertsPath", filename,
                             &pconf->additional_cert_paths) < 0) {
    log_error("load_config_value_list fail");
    free_pledge_config_content(pconf);
    return -1;
  }

  return 0;
}

void free_config_content(struct brski_config *const config) {
  free_pledge_config_content(&config->pconf);
  free_registrar_config_content(&config->rconf);
}

int load_brski_config(const char *filename, struct brski_config *const config) {
  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    log_errno("Couldn't open %s config file.", filename);
    return -1;
  }
  fclose(fp);

  if (load_pledge_config(filename, &config->pconf) < 0) {
    log_error("load_pledge_config fail");
    return -1;
  }

  if (load_registrar_config(filename, &config->rconf) < 0) {
    log_error("load_server_config fail");
    return -1;
  }

  return 0;
}
