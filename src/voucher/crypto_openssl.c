/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the openssl crypto wrapper
 * utilities.
 */

#include <stddef.h>
#include <stdint.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <sys/types.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "../utils/log.h"
#include "../utils/os.h"

#include "crypto_defs.h"

ssize_t evpkey_to_buf(const EVP_PKEY *pkey, uint8_t **key) {
  BUF_MEM *ptr = NULL;
  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_error("BIO_new fail");
    return -1;
  }

  if (i2d_PrivateKey_bio(mem, pkey) != 1) {
    log_error("i2d_PrivateKey_bio fail");
    BIO_free(mem);
    return -1;
  }

  BIO_get_mem_ptr(mem, &ptr);
  ssize_t length = ptr->length;
  if ((*key = (uint8_t *)sys_zalloc(ptr->length)) == NULL) {
    log_errno("sys_zalloc");
    BIO_free(mem);
    return -1;
  }

  sys_memcpy(*key, ptr->data, ptr->length);

  BIO_free(mem);
  return length;
}

ssize_t crypto_generate_rsakey(int bits, uint8_t **key) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  *key = NULL;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
    log_error("EVP_PKEY_CTX_new_id fail with code=%d", ERR_get_error());
    return -1;
  }

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_error("EVP_PKEY_keygen_init fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)) {
    log_error("EVP_PKEY_CTX_set_rsa_keygen_bits fail with code=%d",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_error("EVP_PKEY_keygen fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  ssize_t length = evpkey_to_buf(pkey, key);

  if (length < 0) {
    log_error("evpkey_to_buf fail");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return length;
}

ssize_t crypto_generate_eckey(uint8_t **key) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL, *params = NULL;

  *key = NULL;
  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL) {
    log_error("EVP_PKEY_CTX_new_id fail with code=%d", ERR_get_error());
    return -1;
  }

  if (!EVP_PKEY_paramgen_init(ctx)) {
    log_error("EVP_PKEY_paramgen_init fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)) {
    log_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid fail with code=%d",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_paramgen(ctx, &params)) {
    log_error("EVP_PKEY_paramgen fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  if ((ctx = EVP_PKEY_CTX_new(params, NULL)) == NULL) {
    log_error("EVP_PKEY_CTX_new fail with code=%d", ERR_get_error());
    EVP_PKEY_free(params);
    return -1;
  }

  EVP_PKEY_free(params);

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_error("EVP_PKEY_keygen_init fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_error("EVP_PKEY_keygen fail with code=%d", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  ssize_t length = evpkey_to_buf(pkey, key);

  if (length < 0) {
    log_error("evpkey_to_buf fail");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return length;
}

CRYPTO_KEY crypto_eckey2context(uint8_t *key, size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, (const unsigned char **)&key,
                             (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%d", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_KEY crypto_rsakey2context(uint8_t *key, size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (const unsigned char **)&key,
                             (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%d", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

void crypto_free_keycontext(CRYPTO_KEY ctx) {
  EVP_PKEY *pkey = (EVP_PKEY *)ctx;
  EVP_PKEY_free(pkey);
}

ssize_t crypto_generate_cert(struct crypto_cert_meta *meta, uint8_t *key,
                             size_t key_length, uint8_t **cert) {
  (void)meta;
  (void)key;
  (void)key_length;
  (void)cert;
  return -1;
}
