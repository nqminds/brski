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

extern "C" {
#include "../../utils/log.h"
#include "../../voucher/array.h"
#include "../../voucher/crypto.h"
#include "../../voucher/serialize.h"
#include "../../voucher/voucher.h"
}

int export_voucher_pledge_request(const struct pledge_config *pconf,
                                  const char *tls_cert_path,
                                  const char *out_path) {
  if (pconf == NULL) {
    log_error("pconf is NULL");
    return -1;
  }

  if (tls_cert_path == NULL) {
    log_error("tls_cert_path is NULL");
    return -1;
  }

  if (out_path == NULL) {
    log_error("out_path is NULL");
    return -1;
  }

  struct tm created_on = {0};
  if (pconf->created_on == NULL) {
    if (get_localtime(&created_on) < 0) {
      log_error("get_localtime fail");
      return -1;
    }
  } else {
    if (serialize_str2time(pconf->created_on, &created_on) < 0) {
      log_error("serialize_str2time fail");
      return -1;
    }
  }

  struct BinaryArray *nonce = NULL;
  if (pconf->nonce != NULL) {
    if ((nonce = (struct BinaryArray *)sys_zalloc(
             sizeof(struct BinaryArray))) == NULL) {
      log_errno("sys_zalloc");
      return -1;
    }

    if ((nonce->length = serialize_base64str2array(
             (const uint8_t *)pconf->nonce, strlen(pconf->nonce),
             &nonce->array)) < 0) {
      log_errno("serialize_base64str2array fail");
      free_binary_array(nonce);
      return -1;
    }
  }

  struct BinaryArray *registrar_tls_cert = NULL;
  struct BinaryArray *pledge_sign_cert = NULL;
  struct BinaryArray *pledge_sign_key = NULL;
  struct BinaryArray *cms = NULL;

  if ((registrar_tls_cert = file_to_x509buf(tls_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto export_voucher_pledge_request_fail;
  }

  if ((pledge_sign_cert = file_to_x509buf(pconf->sign_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto export_voucher_pledge_request_fail;
  }

  if ((pledge_sign_key = file_to_keybuf(pconf->sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto export_voucher_pledge_request_fail;
  }

  cms = sign_pledge_voucher_request(&created_on, pconf->serial_number, nonce,
                                    registrar_tls_cert, pledge_sign_cert,
                                    pledge_sign_key, NULL);

  if (cms == NULL) {
    log_error("sign_pledge_voucher_request fail");
    goto export_voucher_pledge_request_fail;
  }

  if (cmsbuf_to_file(cms, out_path) < 0) {
    log_error("cmsbuf_to_file fail");
    goto export_voucher_pledge_request_fail;
  }

  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_binary_array(cms);

  return 0;
export_voucher_pledge_request_fail:
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_binary_array(cms);

  return -1;
}
