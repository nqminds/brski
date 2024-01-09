/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the wolfssl crypto wrapper
 * utilities.
 */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "../utils/log.h"
#include "../utils/os.h"

#include "crypto_defs.h"

CRYPTO_CERT crypto_copycert(CRYPTO_CERT cert) {
  (void)cert;
  return NULL;
}

ssize_t crypto_generate_rsakey(int bits, uint8_t **key) {
  (void)bits;
  (void)key;
  return -1;
}

ssize_t crypto_generate_eckey(uint8_t **key) {
  (void)key;
  return -1;
}

CRYPTO_KEY crypto_eckey2context(uint8_t *key, size_t length) {
  (void)key;
  (void)length;
  return NULL;
}

CRYPTO_KEY crypto_rsakey2context(uint8_t *key, size_t length) {
  (void)key;
  (void)length;
  return NULL;
}

void crypto_free_keycontext(CRYPTO_KEY ctx) { (void)ctx; }
void crypto_free_certcontext(CRYPTO_CERT cert) { (void)cert; }

ssize_t crypto_generate_eccert(struct crypto_cert_meta *meta, uint8_t *key,
                               size_t key_length, uint8_t **cert) {
  (void)meta;
  (void)key;
  (void)key_length;
  (void)cert;
  return -1;
}

ssize_t crypto_generate_rsacert(struct crypto_cert_meta *meta, uint8_t *key,
                                size_t key_length, uint8_t **cert) {
  (void)meta;
  (void)key;
  (void)key_length;
  (void)cert;
  return -1;
}

ssize_t crypto_sign_eccms(uint8_t *data, size_t data_length, uint8_t *cert,
                          size_t cert_length, uint8_t *key, size_t key_length,
                          struct BinaryArrayList *certs, uint8_t **cms) {
  (void)data;
  (void)data_length;
  (void)cert;
  (void)cert_length;
  (void)key;
  (void)key_length;
  (void)certs;
  (void)cms;

  return -1;
}

ssize_t crypto_sign_rsacms(uint8_t *data, size_t data_length, uint8_t *cert,
                           size_t cert_length, uint8_t *key, size_t key_length,
                           struct BinaryArrayList *certs, uint8_t **cms) {
  (void)data;
  (void)data_length;
  (void)cert;
  (void)cert_length;
  (void)key;
  (void)key_length;
  (void)certs;
  (void)cms;

  return -1;
}
