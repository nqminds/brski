/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the pledge utils functions.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pledge_config.h"

#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
#include "../config.h"

struct BinaryArray *
voucher_pledge_request_to_array(const struct pledge_config *pconf,
                                const struct BinaryArray *registrar_tls_cert) {
  if (pconf == NULL) {
    log_error("pconf is NULL");
    return NULL;
  }

  if (registrar_tls_cert == NULL) {
    log_error("registrar_tls_cert is NULL");
    return NULL;
  }

  struct tm created_on = {0};
  if (pconf->created_on == NULL) {
    if (get_localtime(&created_on) < 0) {
      log_error("get_localtime fail");
      return NULL;
    }
  } else {
    if (serialize_str2time(pconf->created_on, &created_on) < 0) {
      log_error("serialize_str2time fail");
      return NULL;
    }
  }

  struct BinaryArray *nonce = NULL;
  if (pconf->nonce != NULL) {
    nonce = init_binary_array();
    if (nonce == NULL) {
      log_errno("init_binary_array");
      return NULL;
    }
    ssize_t length;
    if ((length = serialize_base64str2array((const uint8_t *)pconf->nonce,
                                            strlen(pconf->nonce),
                                            &nonce->array)) < 0) {
      log_errno("serialize_base64str2array fail");
      free_binary_array(nonce);
      return NULL;
    }
    nonce->length = length;
  }

  struct BinaryArray *pledge_sign_cert = NULL;
  struct BinaryArray *pledge_sign_key = NULL;
  struct BinaryArrayList *additional_pledge_certs = NULL;
  struct BinaryArray *cms = NULL;

  if ((pledge_sign_cert = file_to_x509buf(pconf->cms_sign_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  if ((pledge_sign_key = file_to_keybuf(pconf->cms_sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  if (load_cert_files(pconf->cms_add_certs_paths, &additional_pledge_certs) <
      0) {
    log_error("load_cert_files");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  cms = sign_pledge_voucher_request(&created_on, pconf->serial_number, nonce,
                                    registrar_tls_cert, pledge_sign_cert,
                                    pledge_sign_key, additional_pledge_certs);

  if (cms == NULL) {
    log_error("sign_pledge_voucher_request fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  free_binary_array(nonce);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_array_list(additional_pledge_certs);

  return cms;
voucher_pledge_request_to_smimefile_fail:
  free_binary_array(nonce);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_array_list(additional_pledge_certs);
  free_binary_array(cms);

  return NULL;
}

int voucher_pledge_request_to_smimefile(const struct pledge_config *pconf,
                                        const struct BinaryArray *registrar_tls_cert,
                                        const char *out_path) {

  if (out_path == NULL) {
    log_error("out_path is NULL");
    return -1;
  }

  struct BinaryArray *cms =
      voucher_pledge_request_to_array(pconf, registrar_tls_cert);

  if (cms == NULL) {
    log_error("voucher_pledge_request_to_array fail");
    return -1;
  }

  if (cmsbuf_to_file(cms, out_path) < 0) {
    log_error("cmsbuf_to_file fail");
    free_binary_array(cms);
    return -1;
  }

  free_binary_array(cms);

  return 0;
}

char *voucher_pledge_request_to_base64(const struct pledge_config *pconf,
                                       const struct BinaryArray *registrar_tls_cert) {
  struct BinaryArray *cms =
      voucher_pledge_request_to_array(pconf, registrar_tls_cert);

  if (cms == NULL) {
    log_error("voucher_pledge_request_to_array fail");
    return NULL;
  }

  char *base64 = NULL;
  if (serialize_array2base64str(cms->array, cms->length, (uint8_t **)&base64) <
      0) {
    log_error("serialize_array2base64str fail");
    free_binary_array(cms);
    return NULL;
  }

  free_binary_array(cms);

  return base64;
}
