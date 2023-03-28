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

extern "C" {
#include "../utils/log.h"
#include "../utils/os.h"
}

#include "http/http.h"
#include "pledge/pledge_config.h"

#define CREATED_ON_SIZE sizeof("9999-12-31T24:59:59Z") + 1
#define MAX_CONFIG_VALUE_SIZE 2048

void free_registrar_config_content(struct registrar_config *rconf) {
  if (rconf != NULL) {
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
  try {
    char *key = new char[MAX_WEB_PATH_LEN];

    ini_gets("registrar", "bindAddress", "0.0.0.0", key, MAX_WEB_PATH_LEN,
             filename);
    strcpy(rconf->http.bindAddress, key);
    delete[] key;

    rconf->http.port = (unsigned int)ini_getl("registrar", "port", 0, filename);

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("registrar", "tlsCertPath", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    rconf->tls_cert_path = key;
    if (!strlen(rconf->tls_cert_path)) {
      rconf->tls_cert_path = NULL;
      delete[] key;
    }

    ini_gets("registrar", "tlsKeyPath", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    rconf->tls_key_path = key;
    if (!strlen(rconf->tls_key_path)) {
      rconf->tls_key_path = NULL;
      delete[] key;
    }
  } catch (...) {
    log_error("failed to allocate key");
    return -1;
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

    if (pconf->additional_certs_path != NULL) {
      sys_free(pconf->additional_certs_path);
    }
  }
}

int load_pledge_config(const char *filename, struct pledge_config *const pconf) {
  try {
    char *key = new char[CREATED_ON_SIZE];

    ini_gets("pledge", "createdOn", "", key, CREATED_ON_SIZE, filename);
    pconf->created_on = key;
    if (!strlen(pconf->created_on)) {
      pconf->created_on = NULL;
      delete[] key;
    }

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("pledge", "serialNumber", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    pconf->serial_number = key;
    if (!strlen(pconf->serial_number)) {
      pconf->serial_number = NULL;
      delete[] key;
    }

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("pledge", "nonce", "", key, MAX_CONFIG_VALUE_SIZE, filename);
    pconf->nonce = key;
    if (!strlen(pconf->nonce)) {
      pconf->nonce = NULL;
      delete[] key;
    }

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("pledge", "cmdSignCertPath", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    pconf->sign_cert_path = key;
    if (!strlen(pconf->sign_cert_path)) {
      pconf->sign_cert_path = key;
      delete[] key;
    }

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("pledge", "cmsSignKeyPath", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    pconf->sign_key_path = key;
    if (!strlen(pconf->sign_key_path)) {
      pconf->sign_key_path = NULL;
      delete[] key;
    }

    key = new char[MAX_CONFIG_VALUE_SIZE];

    ini_gets("pledge", "cmsAdditionalCertsPath", "", key, MAX_CONFIG_VALUE_SIZE,
             filename);
    pconf->additional_certs_path = key;
    if (!strlen(pconf->additional_certs_path)) {
      pconf->additional_certs_path = NULL;
      delete[] key;
    }
  } catch (...) {
    log_error("failed to allocate key");
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
