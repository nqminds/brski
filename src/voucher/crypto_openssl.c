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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>
#include <sys/types.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "../utils/log.h"
#include "../utils/os.h"

#include "crypto_defs.h"

static ssize_t evpkey_to_derbuf(const EVP_PKEY *pkey, uint8_t **key) {
  *key = NULL;

  int length = i2d_PrivateKey(pkey, key);
  if (length < 0) {
    log_error("i2d_PrivateKey fail with code=%d", ERR_get_error());
    return -1;
  }

  return (ssize_t)length;
}

static ssize_t cert_to_derbuf(const X509 *x509, uint8_t **cert) {
  /*
  For OpenSSL 0.9.7 and later if *cert is NULL memory will be allocated
  for a buffer and the encoded data written to it. In this case *cert is
  not incremented and it points to the start of the data just written.
  */

  *cert = NULL;

  int length = i2d_X509(x509, cert);
  if (length < 0) {
    log_error("i2d_X509 fail with code=%d", ERR_get_error());
    return -1;
  }

  return (ssize_t)length;
}

static ssize_t cms_to_derbuf(CMS_ContentInfo *content, uint8_t **cms) {
  *cms = NULL;

  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (!i2d_CMS_bio(mem, content)) {
    log_error("i2d_CMS_bio fail with code=%d", ERR_get_error());
    BIO_free(mem);
    return -1;
  }

  BUF_MEM *ptr = NULL;

  BIO_get_mem_ptr(mem, &ptr);
  ssize_t length = ptr->length;

  if ((*cms = (uint8_t *)sys_zalloc(length)) == NULL) {
    log_errno("sys_zalloc");
    BIO_free(mem);
    return -1;
  }

  sys_memcpy(*cms, ptr->data, length);

  BIO_free(mem);

  return length;
}

ssize_t crypto_generate_rsakey(int bits, uint8_t **key) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

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

  ssize_t length = evpkey_to_derbuf(pkey, key);

  if (length < 0) {
    log_error("evpkey_to_derbuf fail");
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

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

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

  ssize_t length = evpkey_to_derbuf(pkey, key);

  if (length < 0) {
    log_error("evpkey_to_derbuf fail");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return length;
}

CRYPTO_KEY crypto_eckey2context(const uint8_t *key, size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key,
                             (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%d", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_KEY crypto_rsakey2context(const uint8_t *key, size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &key,
                             (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%d", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_CERT crypto_cert2context(const uint8_t *cert, size_t length) {
  X509 *pcert = NULL;
  const unsigned char *pp = (unsigned char *) cert; 
  if (d2i_X509(&pcert, &pp, length) == NULL) {
    log_error("d2i_X509 fail with code=%d", ERR_get_error());
    return NULL;
  }

  CRYPTO_CERT ctx = (CRYPTO_CERT)pcert;
  return ctx;
}

void crypto_free_keycontext(CRYPTO_KEY ctx) {
  EVP_PKEY *pkey = (EVP_PKEY *)ctx;
  EVP_PKEY_free(pkey);
}

static int set_certificate_serialnumber(X509 *x509, uint64_t serial_number) {
  ASN1_INTEGER *sn = ASN1_INTEGER_new();

  if (sn == NULL) {
    log_error("ASN1_INTEGER_new fail");
    return -1;
  }

  if (!ASN1_INTEGER_set_uint64(sn, serial_number)) {
    log_error("ASN1_INTEGER_set_uint64 fail");
    ASN1_INTEGER_free(sn);
    return -1;
  }

  if (!X509_set_serialNumber(x509, sn)) {
    log_error("X509_set_serialNumber fail");
    ASN1_INTEGER_free(sn);
    return -1;
  }

  ASN1_INTEGER_free(sn);
  return 0;
}

static X509_NAME *add_x509name_keyvalues(struct keyvalue_list *pairs) {
  X509_NAME *name = X509_NAME_new();

  if (name == NULL) {
    log_error("X509_NAME_new fail");
    return NULL;
  }

  struct keyvalue_list *el = NULL;
  dl_list_for_each(el, &pairs->list, struct keyvalue_list, list) {
    if (el->key == NULL) {
      log_error("key is NULL");
      X509_NAME_free(name);
      return NULL;
    }

    if (el->value == NULL) {
      log_error("key is NULL");
      X509_NAME_free(name);
      return NULL;
    }

    log_trace("%s %s", el->key, el->value);
    if (!X509_NAME_add_entry_by_txt(name, el->key, MBSTRING_ASC,
                                    (unsigned char *)el->value, -1, -1, 0)) {
      log_error("X509_NAME_add_entry_by_txt code=%d", ERR_get_error());
      X509_NAME_free(name);
      return NULL;
    }
  }

  return name;
}

static int set_certificate_meta(X509 *x509, struct crypto_cert_meta *meta) {
  if (set_certificate_serialnumber(x509, meta->serial_number) < 0) {
    log_error("set_certificate_serialnumber fail");
    return -1;
  }

  /* certificate expiration date: 365 days from now (60s * 60m * 24h * 365d) */
  if (X509_gmtime_adj(X509_get_notBefore(x509), meta->not_before) == NULL) {
    log_error("X509_gmtime_adj fail");
    return -1;
  }

  if (X509_gmtime_adj(X509_get_notAfter(x509), meta->not_after) == NULL) {
    log_error("X509_gmtime_adj fail");
    return -1;
  }

  if (meta->issuer != NULL) {
    X509_NAME *name = add_x509name_keyvalues(meta->issuer);
    if (name == NULL) {
      log_error("add_x509name_keyvalues fail");
      return -1;
    }

    if (!X509_set_issuer_name(x509, name)) {
      log_error("X509_set_issuer_name fail");
      X509_NAME_free(name);
      return -1;
    }

    X509_NAME_free(name);
  }

  if (meta->subject != NULL) {
    X509_NAME *name = add_x509name_keyvalues(meta->subject);
    if (name == NULL) {
      log_error("add_x509name_keyvalues fail");
      return -1;
    }

    if (!X509_set_subject_name(x509, name)) {
      log_error("X509_set_subject_name fail");
      X509_NAME_free(name);
      return -1;
    }

    X509_NAME_free(name);
  }

  return 0;
}

static int sign_sha256_certificate(X509 *x509, EVP_PKEY *pkey) {
  if (!X509_set_pubkey(x509, pkey)) {
    log_error("X509_set_pubkey fail with code=%d", ERR_get_error());
    return -1;
  }

  /* sign the certificate with the key. */
  if (!X509_sign(x509, pkey, EVP_sha256())) {
    log_error("X509_sign fail with code=%d", ERR_get_error());
    return -1;
  }

  return 0;
}

static ssize_t unsigned_cert_to_derbuf(X509 *x509, EVP_PKEY *pkey, uint8_t **cert) {
  if (sign_sha256_certificate(x509, pkey) < 0) {
    log_error("sign_sha256_certificate fail");
    return -1;
  }

  ssize_t length = cert_to_derbuf(x509, cert);
  if (length < 0) {
    log_error("cert_to_derbuf fail");
    return -1;
  }

  return length;
}

ssize_t crypto_generate_eccert(struct crypto_cert_meta *meta, uint8_t *key,
                               size_t key_length, uint8_t **cert) {
  *cert = NULL;

  if (meta == NULL) {
    log_error("met param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (cert == NULL) {
    log_error("cert aparam is NULL");
    return -1;
  }

  *cert = NULL;

  X509 *x509 = X509_new();

  if (x509 == NULL) {
    log_error("X509_new fail");
    return -1;
  }

  if (set_certificate_meta(x509, meta) < 0) {
    log_error("set_certificate_meta fail");
    X509_free(x509);
    return -1;
  }

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_eckey2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_eckey2context fail");
    X509_free(x509);
    return -1;
  }

  ssize_t length = unsigned_cert_to_derbuf(x509, pkey, cert);
  if (length < 0) {
    log_error("unsigned_cert_to_derbuf fail");
  }

  EVP_PKEY_free(pkey);
  X509_free(x509);

  return length;
}

ssize_t crypto_generate_rsacert(struct crypto_cert_meta *meta, uint8_t *key,
                                size_t key_length, uint8_t **cert) {
  *cert = NULL;

  if (meta == NULL) {
    log_error("met aparam is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key aparam is NULL");
    return -1;
  }

  if (cert == NULL) {
    log_error("cert aparam is NULL");
    return -1;
  }

  X509 *x509 = X509_new();

  if (x509 == NULL) {
    log_error("X509_new fail");
    return -1;
  }

  if (set_certificate_meta(x509, meta) < 0) {
    log_error("set_certificate_meta fail");
    X509_free(x509);
    return -1;
  }

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_rsakey2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_eckey2context fail");
    X509_free(x509);
    return -1;
  }

  ssize_t length = unsigned_cert_to_derbuf(x509, pkey, cert);
  if (length < 0) {
    log_error("unsigned_cert_to_derbuf fail");
  }

  EVP_PKEY_free(pkey);
  X509_free(x509);

  return length;
}

static STACK_OF(X509) *get_certificate_stack(struct buffer_list *certs) {
  STACK_OF(X509) *cert_stack = sk_X509_new_null();

  if (cert_stack == NULL) {
    log_trace("sk_X509_new_null fail with code=%d", ERR_get_error());
    return NULL;
  }

  struct buffer_list *el = NULL;
  dl_list_for_each(el, &certs->list, struct buffer_list, list) {
    X509 *x509 = crypto_cert2context(el->buf, el->length);
    if (x509 == NULL) {
      log_error("crypto_cert2context fail");
      sk_X509_pop_free(cert_stack, X509_free);
      return NULL;
    }
    sk_X509_push(cert_stack, x509);
  }

  return cert_stack;
}

static ssize_t sign_withkey_cms(uint8_t *data, size_t data_length, uint8_t *cert,
                        size_t cert_length, EVP_PKEY *pkey,
                        struct buffer_list *certs, uint8_t **cms) {
  unsigned int flags = CMS_BINARY;
  
  BIO *mem_data = BIO_new_ex(NULL, BIO_s_mem());

  if (BIO_write(mem_data, data, data_length) < 0) {
    log_trace("BIO_write fail with code=%d", ERR_get_error());
    BIO_free(mem_data);
    return -1;
  }

  X509 *signcert = crypto_cert2context(cert, cert_length);
  if (signcert == NULL) {
    log_error("crypto_cert2context fail");
    BIO_free(mem_data);
    return -1;
  }

  STACK_OF(X509) *cert_stack = NULL;
  if (certs != NULL) {
    if((cert_stack = get_certificate_stack(certs)) == NULL) {
      log_error("get_certificate_stack fail");
      X509_free(signcert);
      BIO_free(mem_data);
      return -1;
    }
  }

  CMS_ContentInfo *content = CMS_sign(signcert, pkey, cert_stack,
                          mem_data, flags);
  
  if (content == NULL) {
    log_trace("CMS_sign fail with code=%d", ERR_get_error());
    X509_free(signcert);
    sk_X509_pop_free(cert_stack, X509_free);
    BIO_free(mem_data);
    return -1;
  }

  if (!CMS_final(content, mem_data, NULL, flags)) {
    log_trace("CMS_final fail with code=%d", ERR_get_error());
    X509_free(signcert);
    sk_X509_pop_free(cert_stack, X509_free);
    BIO_free(mem_data);
    return -1;
  }

  /* Get the DER format of the CMS structure */
  ssize_t length = cms_to_derbuf(content, cms);
  if (length < 0) {
    log_error("cms_to_derbuf fail");
    X509_free(signcert);
    sk_X509_pop_free(cert_stack, X509_free);
    BIO_free(mem_data);
    return -1;
  }

  X509_free(signcert);
  sk_X509_pop_free(cert_stack, X509_free);
  BIO_free(mem_data);
  return length;
}

ssize_t crypto_sign_eccms(uint8_t *data, size_t data_length, uint8_t *cert,
                        size_t cert_length, uint8_t *key, size_t key_length,
                        struct buffer_list *certs, uint8_t **cms) {
  if (data == NULL) {
    log_error("data param is NULL");
    return -1;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (cms == NULL) {
    log_error("cms param is NULL");
    return -1;
  }

  *cms = NULL;

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_eckey2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_eckey2context fail");
    return -1;
  }

  ssize_t length = sign_withkey_cms(data, data_length, cert, cert_length, pkey, certs, cms);

  if (length < 0) {
    log_error("sign_withkey_eccms fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return length;
}

ssize_t crypto_sign_rsacms(uint8_t *data, size_t data_length, uint8_t *cert,
                        size_t cert_length, uint8_t *key, size_t key_length,
                        struct buffer_list *certs, uint8_t **cms) {
  if (data == NULL) {
    log_error("data param is NULL");
    return -1;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (cms == NULL) {
    log_error("cms param is NULL");
    return -1;
  }

  *cms = NULL;

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_rsakey2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_eckey2context fail");
    return -1;
  }

  ssize_t length = sign_withkey_cms(data, data_length, cert, cert_length, pkey, certs, cms);

  if (length < 0) {
    log_error("sign_withkey_eccms fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return length;
}
