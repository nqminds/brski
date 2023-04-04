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

void free_masa_config_content(struct masa_config *mconf) {
  if (mconf != NULL) {
    if (mconf->bind_address != NULL) {
      sys_free(mconf->bind_address);
      mconf->bind_address = NULL;
    }

    if (mconf->tls_cert_path != NULL) {
      sys_free(mconf->tls_cert_path);
      mconf->tls_cert_path = NULL;
    }

    if (mconf->tls_key_path != NULL) {
      sys_free(mconf->tls_key_path);
      mconf->tls_key_path = NULL;
    }

    if (mconf->cms_sign_cert_path != NULL) {
      sys_free(mconf->cms_sign_cert_path);
      mconf->cms_sign_cert_path = NULL;
    }

    if (mconf->cms_sign_key_path != NULL) {
      sys_free(mconf->cms_sign_key_path);
      mconf->cms_sign_key_path = NULL;
    }

    free_array_list(mconf->cms_add_certs_paths);
    mconf->cms_add_certs_paths = NULL;
    free_array_list(mconf->cms_verify_certs_paths);
    mconf->cms_verify_certs_paths = NULL;
    free_array_list(mconf->cms_verify_store_paths);
    mconf->cms_verify_store_paths = NULL;
  }
}

int load_masa_config(const char *filename,
                          struct masa_config *const mconf) {
  char *value = NULL;

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_masa_config_content(mconf);
    return -1;
  }

  ini_gets("masa", "bindAddress", "0.0.0.0", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  mconf->bind_address = value;
  if (!strlen(mconf->bind_address)) {
    mconf->bind_address = NULL;
    sys_free(value);
  }

  mconf->port = (unsigned int)ini_getl("masa", "port", 0, filename);

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_masa_config_content(mconf);
    return -1;
  }

  ini_gets("masa", "tlsCertPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  mconf->tls_cert_path = value;
  if (!strlen(mconf->tls_cert_path)) {
    mconf->tls_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_masa_config_content(mconf);
    return -1;
  }

  ini_gets("masa", "tlsKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  mconf->tls_key_path = value;
  if (!strlen(mconf->tls_key_path)) {
    mconf->tls_key_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_masa_config_content(mconf);
    return -1;
  }

  ini_gets("masa", "cmsSignCertPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  mconf->cms_sign_cert_path = value;
  if (!strlen(mconf->cms_sign_cert_path)) {
    mconf->cms_sign_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_masa_config_content(mconf);
    return -1;
  }

  ini_gets("masa", "cmsSignKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  mconf->cms_sign_key_path = value;
  if (!strlen(mconf->cms_sign_key_path)) {
    mconf->cms_sign_key_path = NULL;
    sys_free(value);
  }

  if (load_config_value_list("masa", "cmsAdditionalCertPath", filename,
                             &mconf->cms_add_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_masa_config_content(mconf);
    return -1;
  }

  if (load_config_value_list("masa", "cmsVerifyCertPath", filename,
                             &mconf->cms_verify_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_masa_config_content(mconf);
    return -1;
  }

  if (load_config_value_list("masa", "cmsVerifyStorePath", filename,
                             &mconf->cms_verify_store_paths) < 0) {
    log_error("load_config_value_list fail");
    free_masa_config_content(mconf);
    return -1;
  }

  return 0;
}

void free_registrar_config_content(struct registrar_config *rconf) {
  if (rconf != NULL) {
    if (rconf->bind_address != NULL) {
      sys_free(rconf->bind_address);
      rconf->bind_address = NULL;
    }

    if (rconf->tls_cert_path != NULL) {
      sys_free(rconf->tls_cert_path);
      rconf->tls_cert_path = NULL;
    }

    if (rconf->tls_key_path != NULL) {
      sys_free(rconf->tls_key_path);
      rconf->tls_key_path = NULL;
    }

    if (rconf->cms_sign_cert_path != NULL) {
      sys_free(rconf->cms_sign_cert_path);
      rconf->cms_sign_cert_path = NULL;
    }

    if (rconf->cms_sign_key_path != NULL) {
      sys_free(rconf->cms_sign_key_path);
      rconf->cms_sign_key_path = NULL;
    }

    free_array_list(rconf->cms_add_certs_paths);
    rconf->cms_add_certs_paths = NULL;
    free_array_list(rconf->cms_verify_certs_paths);
    rconf->cms_verify_certs_paths = NULL;
    free_array_list(rconf->cms_verify_store_paths);
    rconf->cms_verify_store_paths = NULL;
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

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_registrar_config_content(rconf);
    return -1;
  }

  ini_gets("registrar", "cmsSignCertPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  rconf->cms_sign_cert_path = value;
  if (!strlen(rconf->cms_sign_cert_path)) {
    rconf->cms_sign_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_registrar_config_content(rconf);
    return -1;
  }

  ini_gets("registrar", "cmsSignKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  rconf->cms_sign_key_path = value;
  if (!strlen(rconf->cms_sign_key_path)) {
    rconf->cms_sign_key_path = NULL;
    sys_free(value);
  }

  if (load_config_value_list("registrar", "cmsAdditionalCertPath", filename,
                             &rconf->cms_add_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_registrar_config_content(rconf);
    return -1;
  }

  if (load_config_value_list("registrar", "cmsVerifyCertPath", filename,
                             &rconf->cms_verify_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_registrar_config_content(rconf);
    return -1;
  }

  if (load_config_value_list("registrar", "cmsVerifyStorePath", filename,
                             &rconf->cms_verify_store_paths) < 0) {
    log_error("load_config_value_list fail");
    free_registrar_config_content(rconf);
    return -1;
  }

  return 0;
}

void free_pledge_config_content(struct pledge_config *const pconf) {
  if (pconf != NULL) {
    if (pconf->created_on != NULL) {
      sys_free(pconf->created_on);
      pconf->created_on = NULL;
    }

    if (pconf->serial_number != NULL) {
      sys_free(pconf->serial_number);
      pconf->serial_number = NULL;
    }

    if (pconf->nonce != NULL) {
      sys_free(pconf->nonce);
      pconf->nonce = NULL;
    }

    if (pconf->cms_sign_cert_path != NULL) {
      sys_free(pconf->cms_sign_cert_path);
      pconf->cms_sign_cert_path = NULL;
    }

    if (pconf->cms_sign_key_path != NULL) {
      sys_free(pconf->cms_sign_key_path);
      pconf->cms_sign_key_path = NULL;
    }

    free_array_list(pconf->cms_add_certs_paths);
    pconf->cms_add_certs_paths = NULL;
    free_array_list(pconf->cms_verify_certs_paths);
    pconf->cms_verify_certs_paths = NULL;
    free_array_list(pconf->cms_verify_store_paths);
    pconf->cms_verify_store_paths = NULL;
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
  pconf->cms_sign_cert_path = value;
  if (!strlen(pconf->cms_sign_cert_path)) {
    pconf->cms_sign_cert_path = NULL;
    sys_free(value);
  }

  if ((value = sys_zalloc(MAX_CONFIG_VALUE_SIZE)) == NULL) {
    log_errno("sys_zalloc");
    free_pledge_config_content(pconf);
    return -1;
  }

  ini_gets("pledge", "cmsSignKeyPath", "", value, MAX_CONFIG_VALUE_SIZE,
           filename);
  pconf->cms_sign_key_path = value;
  if (!strlen(pconf->cms_sign_key_path)) {
    pconf->cms_sign_key_path = NULL;
    sys_free(value);
  }

  if (load_config_value_list("pledge", "cmsAdditionalCertPath", filename,
                             &pconf->cms_add_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_pledge_config_content(pconf);
    return -1;
  }

  if (load_config_value_list("pledge", "cmsVerifyCertPath", filename,
                             &pconf->cms_verify_certs_paths) < 0) {
    log_error("load_config_value_list fail");
    free_pledge_config_content(pconf);
    return -1;
  }

  if (load_config_value_list("pledge", "cmsVerifyStorePath", filename,
                             &pconf->cms_verify_store_paths) < 0) {
    log_error("load_config_value_list fail");
    free_pledge_config_content(pconf);
    return -1;
  }

  return 0;
}

void free_config_content(struct brski_config *const config) {
  free_pledge_config_content(&config->pconf);
  free_registrar_config_content(&config->rconf);
  free_masa_config_content(&config->mconf);
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
    free_config_content(config);
    return -1;
  }

  if (load_registrar_config(filename, &config->rconf) < 0) {
    log_error("load_registrar_config fail");
    free_config_content(config);
    return -1;
  }

  if (load_masa_config(filename, &config->mconf) < 0) {
    log_error("load_masa_config fail");
    free_config_content(config);
    return -1;
  }

  return 0;
}
