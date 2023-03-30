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

int load_cert_files(struct BinaryArrayList *cert_paths, struct BinaryArrayList **out) {
  *out = NULL;

  if (cert_paths == NULL) {
    return 0;
  }

  if (!dl_list_len(&cert_paths->list)) {
    return 0;
  }

  if ((*out = init_array_list()) == NULL) {
    log_error("init_array_list fail");
    return -1;
  }

  struct BinaryArrayList *cert_path = NULL;
  dl_list_for_each(cert_path, &cert_paths->list, struct BinaryArrayList, list) {
    struct BinaryArray *cert = NULL;
    char *cert_path_str = (char *)cert_path->arr;
    if ((cert = file_to_x509buf(cert_path_str)) == NULL) {
      log_error("file_to_x509buf fail");
      free_array_list(*out);
      return -1;
    }

    if (push_array_list(*out, cert->array, cert->length, 0) < 0) {
      log_error("push_array_list fail");
      free_binary_array(cert);
      free_array_list(*out);
      return -1;
    }
    free_binary_array(cert);
  }

  return 0;
}

struct BinaryArray* voucher_pledge_request_to_array(const struct pledge_config *pconf,
                                  const char *tls_cert_path) {
  if (pconf == NULL) {
    log_error("pconf is NULL");
    return NULL;
  }

  if (tls_cert_path == NULL) {
    log_error("tls_cert_path is NULL");
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
    if ((nonce = (struct BinaryArray *)sys_zalloc(
             sizeof(struct BinaryArray))) == NULL) {
      log_errno("sys_zalloc");
      return NULL;
    }
    ssize_t length;
    if ((length = serialize_base64str2array(
             (const uint8_t *)pconf->nonce, strlen(pconf->nonce),
             &nonce->array)) < 0) {
      log_errno("serialize_base64str2array fail");
      free_binary_array(nonce);
      return NULL;
    } 
    nonce->length = length;
  }

  struct BinaryArray *registrar_tls_cert = NULL;
  struct BinaryArray *pledge_sign_cert = NULL;
  struct BinaryArray *pledge_sign_key = NULL;
  struct BinaryArrayList *additional_pledge_certs = NULL;
  struct BinaryArray *cms = NULL;

  if ((registrar_tls_cert = file_to_x509buf(tls_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  if ((pledge_sign_cert = file_to_x509buf(pconf->sign_cert_path)) == NULL) {
    log_error("file_to_x509buf fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  if ((pledge_sign_key = file_to_keybuf(pconf->sign_key_path)) == NULL) {
    log_error("file_to_keybuf fail");
    goto voucher_pledge_request_to_smimefile_fail;
  }

  if (load_cert_files(pconf->additional_cert_paths, &additional_pledge_certs) < 0) {
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
  free_binary_array(registrar_tls_cert);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_array_list(additional_pledge_certs);

  return cms;
voucher_pledge_request_to_smimefile_fail:
  free_binary_array(nonce);
  free_binary_array(registrar_tls_cert);
  free_binary_array(pledge_sign_cert);
  free_binary_array(pledge_sign_key);
  free_array_list(additional_pledge_certs);
  free_binary_array(cms);

  return NULL;
}

int voucher_pledge_request_to_smimefile(const struct pledge_config *pconf,
                                  const char *tls_cert_path,
                                  const char *out_path) {
  
  if (out_path == NULL) {
    log_error("out_path is NULL");
    return -1;
  }

  struct BinaryArray *cms = voucher_pledge_request_to_array(pconf, tls_cert_path);

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

char * voucher_pledge_request_to_base64(const struct pledge_config *pconf,
                                  const char *tls_cert_path) {
  struct BinaryArray *cms = voucher_pledge_request_to_array(pconf, tls_cert_path);

  if (cms == NULL) {
    log_error("voucher_pledge_request_to_array fail");
    return NULL;
  }

  char *base64 = NULL;
  if (serialize_array2base64str(cms->array, cms->length, (uint8_t **)&base64) < 0) {
    log_error("serialize_array2base64str fail");
    free_binary_array(cms);
    return NULL;
  }

  free_binary_array(cms);

  return base64;
}