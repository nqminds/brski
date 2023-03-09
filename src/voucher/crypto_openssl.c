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
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
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
    log_error("i2d_PrivateKey fail with code=%lu", ERR_get_error());
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
    log_error("i2d_X509 fail with code=%lu", ERR_get_error());
    return -1;
  }

  return (ssize_t)length;
}

static ssize_t bio_to_ptr(const BIO *mem, uint8_t **data) {
  *data = NULL;

  BUF_MEM *ptr = NULL;
  BIO_get_mem_ptr((BIO *)mem, &ptr);
  ssize_t length = ptr->length;

  if (length) {
    if ((*data = (uint8_t *)sys_zalloc(length)) == NULL) {
      log_errno("sys_zalloc");
      return -1;
    }

    sys_memcpy(*data, ptr->data, length);
  }

  return length;
}

static ssize_t cms_to_derbuf(const CMS_ContentInfo *content, uint8_t **cms) {
  *cms = NULL;

  BIO *mem = BIO_new_ex(NULL, BIO_s_mem());

  if (mem == NULL) {
    log_error("BIO_new_ex fail with code=%lu", ERR_get_error());
    return -1;
  }

  if (!i2d_CMS_bio(mem, (CMS_ContentInfo *)content)) {
    log_error("i2d_CMS_bio fail with code=%lu", ERR_get_error());
    BIO_free(mem);
    return -1;
  }

  ssize_t length = bio_to_ptr(mem, cms);
  if (length < 0) {
    log_error("bio_to_ptr fail");
    BIO_free(mem);
    return -1;
  }

  BIO_free(mem);
  return length;
}

static X509_CRL *derbuf_to_crl(const uint8_t *crl, const size_t length) {
  X509_CRL *crl_cert = NULL;
  const unsigned char *pp = (unsigned char *)crl;
  if (d2i_X509_CRL(&crl_cert, &pp, length) == NULL) {
    log_error("d2i_X509_CRL fail with code=%lu", ERR_get_error());
    return NULL;
  }

  return crl_cert;
}

static CMS_ContentInfo *derbuf_to_cms(const uint8_t *cms,
                                      const ssize_t cms_length) {
  CMS_ContentInfo *content = NULL;
  const unsigned char *pp = (unsigned char *)cms;
  if (d2i_CMS_ContentInfo(&content, &pp, cms_length) == NULL) {
    log_error("d2i_CMS_ContentInfo fail with code=%lu", ERR_get_error());
    return NULL;
  }

  return content;
}

ssize_t crypto_generate_rsakey(const int bits, uint8_t **key) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  *key = NULL;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
    log_error("EVP_PKEY_CTX_new_id fail with code=%lu", ERR_get_error());
    return -1;
  }

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_error("EVP_PKEY_keygen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)) {
    log_error("EVP_PKEY_CTX_set_rsa_keygen_bits fail with code=%lu",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_error("EVP_PKEY_keygen fail with code=%lu", ERR_get_error());
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
    log_error("EVP_PKEY_CTX_new_id fail with code=%lu", ERR_get_error());
    return -1;
  }

  if (!EVP_PKEY_paramgen_init(ctx)) {
    log_error("EVP_PKEY_paramgen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)) {
    log_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid fail with code=%lu",
              ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_paramgen(ctx, &params)) {
    log_error("EVP_PKEY_paramgen fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  if ((ctx = EVP_PKEY_CTX_new(params, NULL)) == NULL) {
    log_error("EVP_PKEY_CTX_new fail with code=%lu", ERR_get_error());
    EVP_PKEY_free(params);
    return -1;
  }

  EVP_PKEY_free(params);

  if (!EVP_PKEY_keygen_init(ctx)) {
    log_error("EVP_PKEY_keygen_init fail with code=%lu", ERR_get_error());
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    log_error("EVP_PKEY_keygen fail with code=%lu", ERR_get_error());
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

CRYPTO_KEY crypto_eckey2context(const uint8_t *key, const size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key, (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%lu", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_KEY crypto_rsakey2context(const uint8_t *key, const size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &key, (long)length)) == NULL) {
    log_error("d2i_PrivateKey fail with code=%lu", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_KEY crypto_key2context(const uint8_t *key, const size_t length) {
  EVP_PKEY *pkey = NULL;
  if ((pkey = d2i_AutoPrivateKey(NULL, &key, (long)length)) == NULL) {
    log_error("d2i_AutoPrivateKey fail with code=%lu", ERR_get_error());
    return NULL;
  }

  CRYPTO_KEY ctx = (CRYPTO_KEY)pkey;
  return ctx;
}

CRYPTO_CERT crypto_cert2context(const uint8_t *cert, const size_t length) {
  X509 *pcert = NULL;
  const unsigned char *pp = (unsigned char *)cert;
  if (d2i_X509(&pcert, &pp, length) == NULL) {
    log_error("d2i_X509 fail with code=%lu", ERR_get_error());
    return NULL;
  }

  CRYPTO_CERT ctx = (CRYPTO_CERT)pcert;
  return ctx;
}

void crypto_free_keycontext(CRYPTO_KEY ctx) {
  EVP_PKEY *pkey = (EVP_PKEY *)ctx;
  EVP_PKEY_free(pkey);
}

static int set_certificate_serialnumber(X509 *x509,
                                        const uint64_t serial_number) {
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

    if (!X509_NAME_add_entry_by_txt(name, el->key, MBSTRING_ASC,
                                    (unsigned char *)el->value, -1, -1, 0)) {
      log_error("X509_NAME_add_entry_by_txt code=%lu", ERR_get_error());
      X509_NAME_free(name);
      return NULL;
    }
  }

  return name;
}

static int set_certificate_meta(X509 *x509,
                                const struct crypto_cert_meta *meta) {
  if (X509_set_version(x509, X509_VERSION_3) != 1) {
    log_error("X509_set_version fail with code=%lu", ERR_get_error());
    return -1;
  }

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

static int sign_sha256_certificate(X509 *x509, const EVP_PKEY *pkey) {
  /* self sign the certificate with the key. */
  if (!X509_sign(x509, (EVP_PKEY *)pkey, EVP_sha256())) {
    log_error("X509_sign fail with code=%lu", ERR_get_error());
    return -1;
  }

  if (X509_verify(x509, (EVP_PKEY *)pkey) < 1) {
    log_error("signaure verification fail");
    return -1;
  }

  return 0;
}

ssize_t crypto_generate_eccert(const struct crypto_cert_meta *meta,
                               const uint8_t *key, const size_t key_length,
                               bool self_sign,
                               uint8_t **cert) {
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
    log_error("cert param is NULL");
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

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_eckey2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_eckey2context fail");
    X509_free(x509);
    return -1;
  }

  if (!X509_set_pubkey(x509, (EVP_PKEY *)pkey)) {
    log_error("X509_set_pubkey fail with code=%lu", ERR_get_error());
    return -1;
  }

  if(self_sign) {
    if (sign_sha256_certificate(x509, pkey) < 0) {
      log_error("sign_sha256_certificate fail");
      EVP_PKEY_free(pkey);
      X509_free(x509);
      return -1;
    }
  }

  ssize_t length = cert_to_derbuf(x509, cert);
  if (length < 0) {
    log_error("cert_to_derbuf fail");
  }

  EVP_PKEY_free(pkey);
  X509_free(x509);

  return length;
}

ssize_t crypto_generate_rsacert(const struct crypto_cert_meta *meta,
                                const uint8_t *key, const size_t key_length,
                                bool self_sign,
                                uint8_t **cert) {
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

  if (!X509_set_pubkey(x509, (EVP_PKEY *)pkey)) {
    log_error("X509_set_pubkey fail with code=%lu", ERR_get_error());
    return -1;
  }

  if(self_sign) {
    if (sign_sha256_certificate(x509, pkey) < 0) {
      log_error("sign_sha256_certificate fail");
      EVP_PKEY_free(pkey);
      X509_free(x509);
      return -1;
    }
  }

  ssize_t length = cert_to_derbuf(x509, cert);
  if (length < 0) {
    log_error("cert_to_derbuf fail");
  }

  EVP_PKEY_free(pkey);
  X509_free(x509);

  return length;
}

ssize_t crypto_sign_cert(const uint8_t *key, const size_t key_length,
                         const size_t cert_length, uint8_t **cert) {
  if (key == NULL) {
    log_error("key param is NULL");
    return -1;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return -1;
  }

  if (*cert == NULL) {
    log_error("cert buffer is NULL");
    return -1;
  }

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_key2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_key2context fail");
    return -1;
  }

  X509 *x509 = crypto_cert2context(*cert, cert_length);
  if (x509 == NULL) {
    log_error("crypto_cert2context fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  if (!X509_sign(x509, (EVP_PKEY *)pkey, EVP_sha256())) {
    log_error("X509_sign fail with code=%lu", ERR_get_error());
    return -1;
  }

  uint8_t *out_cert = NULL;
  ssize_t out_cert_length = cert_to_derbuf(x509, &out_cert);
  if (out_cert_length < 0) {
    log_error("cert_to_derbuf fail");
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return -1;
  }

  /* Assign the new signed certificate */
  sys_free(*cert);
  *cert = out_cert;

  X509_free(x509);
  EVP_PKEY_free(pkey);
  return out_cert_length;
}

static STACK_OF(X509) * get_certificate_stack(const struct buffer_list *certs) {
  STACK_OF(X509) *cert_stack = sk_X509_new_null();

  if (cert_stack == NULL) {
    log_error("sk_X509_new_null fail with code=%lu", ERR_get_error());
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

void free_x509_store_cert(void *cert, const int flags) {
  if (cert != NULL) {
    if (flags == CRYPTO_CERTIFICATE_VALID) {
      X509_free((X509 *)cert);
    } else if (flags == CRYPTO_CERTIFICATE_CRL) {
      X509_CRL_free((X509_CRL *)cert);
    }
  }
}

void free_x509_store(X509_STORE *store, struct ptr_list *x509_store_list) {
  if (store != NULL) {
    X509_STORE_free(store);
  }

  free_ptr_list(x509_store_list, free_x509_store_cert);
}

static X509_STORE *get_certificate_store(const struct buffer_list *store,
                                         struct ptr_list **x509_store_list) {
  *x509_store_list = NULL;

  /* Initialize the ptr list to store the pointers to converted ceritificates
      and crls. The reason is X509_STORE_free doesn't free the stored cert
     pointers.
  */
  if ((*x509_store_list = init_ptr_list()) == NULL) {
    log_error("init_ptr_list fail");
    return NULL;
  }

  X509_STORE *x509_store = X509_STORE_new();

  if (x509_store == NULL) {
    log_error("X509_STORE_new fail with code=%lu", ERR_get_error());
    free_x509_store(x509_store, *x509_store_list);
    return NULL;
  }

  struct buffer_list *el = NULL;
  dl_list_for_each(el, &store->list, struct buffer_list, list) {
    enum CRYPTO_CERTIFICATE_TYPE type = (enum CRYPTO_CERTIFICATE_TYPE)el->flags;
    void *ptr = NULL;
    if (type == CRYPTO_CERTIFICATE_VALID) {
      X509 *x509 = crypto_cert2context(el->buf, el->length);
      if (x509 == NULL) {
        log_error("crypto_cert2context fail");
        free_x509_store(x509_store, *x509_store_list);
        return NULL;
      }

      if (!X509_STORE_add_cert(x509_store, x509)) {
        log_error("X509_STORE_add_cert fail with code=%lu", ERR_get_error());
        free_x509_store(x509_store, *x509_store_list);
        return NULL;
      }

      ptr = (void *)x509;
    } else if (type == CRYPTO_CERTIFICATE_CRL) {
      X509_CRL *x509_crl = derbuf_to_crl(el->buf, el->length);
      if (x509_crl == NULL) {
        log_error("derbuf_to_crl fail");
        free_x509_store(x509_store, *x509_store_list);
        return NULL;
      }

      if (!X509_STORE_add_crl(x509_store, x509_crl)) {
        log_error("X509_STORE_add_crl fail with code=%lu", ERR_get_error());
        free_x509_store(x509_store, *x509_store_list);
        return NULL;
      }

      ptr = (void *)x509_crl;
    }
    if (push_ptr_list(*x509_store_list, ptr, el->flags) < 0) {
      log_error("push_ptr_list fail");
      free_x509_store(x509_store, *x509_store_list);
      return NULL;
    }
  }

  return x509_store;
}

int crypto_verify_cert(const uint8_t *cert, const size_t cert_length, const struct buffer_list *certs,
                          const struct buffer_list *store) {
  if (cert == NULL) {
    log_error("cert param is NULL");
    return -1;
  }

  if (certs == NULL) {
    log_error("certs param is NULL");
    return -1;
  }

  X509 *x509 = crypto_cert2context(cert, cert_length);
  if (x509 == NULL) {
    log_error("crypto_cert2context fail");
    return -1;
  }

  STACK_OF(X509) *cert_stack = NULL;
  if ((cert_stack = get_certificate_stack(certs)) == NULL) {
    log_error("get_certificate_stack fail");
    X509_free(x509);
    return -1;
  }

  X509_STORE *cert_store = NULL;
  struct ptr_list *x509_store_list = NULL;
  if (store != NULL) {
    cert_store = get_certificate_store(store, &x509_store_list);

    if (cert_store == NULL) {
      log_error("get_certificate_store fail");
      sk_X509_pop_free(cert_stack, X509_free);
      X509_free(x509);
      return -1;
    }
  }

  STACK_OF(X509) *out_cert_stack = X509_build_chain(x509, cert_stack, cert_store, 0, NULL, NULL);
  if (out_cert_stack == NULL) {
    log_error("X509_build_chain fail");
  }

  int ret = (out_cert_stack != NULL) ? 0 : -1;

  if (sk_X509_num(out_cert_stack) < 1) {
    log_error("cert stack is empty");
    ret = -1;
  }

  free_x509_store(cert_store, x509_store_list);
  sk_X509_pop_free(cert_stack, X509_free);
  sk_X509_pop_free(out_cert_stack, X509_free);
  X509_free(x509);
  return ret;
}

void cms_to_tmpfile(CMS_ContentInfo *cms, const char *filename) {
  BIO *out = BIO_new_file(filename, "w");
  if (out == NULL) {
    log_error("BIO_new_ex fail with code=%lu", ERR_get_error());
    return;
  }

  if (!SMIME_write_CMS(out, cms, NULL, CMS_TEXT)) {
    log_error("SMIME_write_CMS fail with code=%s",
              ERR_reason_error_string(ERR_get_error()));
    BIO_free(out);
  }

  BIO_free(out);
}

static ssize_t sign_withkey_cms(const uint8_t *data, const size_t data_length,
                                const uint8_t *cert, const size_t cert_length,
                                const EVP_PKEY *pkey,
                                const struct buffer_list *certs,
                                uint8_t **cms) {
  BIO *mem_data = BIO_new_ex(NULL, BIO_s_mem());
  if (mem_data == NULL) {
    log_error("BIO_new_ex fail with code=%lu", ERR_get_error());
    return -1;
  }

  if (BIO_write(mem_data, data, data_length) < 0) {
    log_error("BIO_write fail with code=%lu", ERR_get_error());
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
    if ((cert_stack = get_certificate_stack(certs)) == NULL) {
      log_error("get_certificate_stack fail");
      X509_free(signcert);
      BIO_free(mem_data);
      return -1;
    }
  }

  unsigned int flags = CMS_BINARY;
  flags &= ~CMS_DETACHED;

  CMS_ContentInfo *content =
      CMS_sign(signcert, (EVP_PKEY *)pkey, cert_stack, mem_data, flags);

  if (content == NULL) {
    log_error("CMS_sign fail with code=%s",
              ERR_reason_error_string(ERR_get_error()));
    goto sign_withkey_cms_fail;
  }

  /* Get the DER format of the CMS structure */
  ssize_t length = cms_to_derbuf(content, cms);
  if (length < 0) {
    log_error("cms_to_derbuf fail");
    goto sign_withkey_cms_fail;
  }

  X509_free(signcert);
  sk_X509_pop_free(cert_stack, X509_free);
  BIO_free(mem_data);
  CMS_ContentInfo_free(content);
  return length;

sign_withkey_cms_fail:
  X509_free(signcert);
  sk_X509_pop_free(cert_stack, X509_free);
  BIO_free(mem_data);
  CMS_ContentInfo_free(content);
  return -1;
}

ssize_t crypto_sign_eccms(const uint8_t *data, const size_t data_length,
                          const uint8_t *cert, const size_t cert_length,
                          const uint8_t *key, const size_t key_length,
                          const struct buffer_list *certs, uint8_t **cms) {
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

  ssize_t length =
      sign_withkey_cms(data, data_length, cert, cert_length, pkey, certs, cms);

  if (length < 0) {
    log_error("sign_withkey_eccms fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return length;
}

ssize_t crypto_sign_rsacms(const uint8_t *data, const size_t data_length,
                           const uint8_t *cert, const size_t cert_length,
                           const uint8_t *key, const size_t key_length,
                           const struct buffer_list *certs, uint8_t **cms) {
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
    log_error("crypto_rsakey2context fail");
    return -1;
  }

  ssize_t length =
      sign_withkey_cms(data, data_length, cert, cert_length, pkey, certs, cms);

  if (length < 0) {
    log_error("sign_withkey_eccms fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return length;
}

ssize_t crypto_sign_cms(const uint8_t *data, const size_t data_length,
                        const uint8_t *cert, const size_t cert_length,
                        const uint8_t *key, const size_t key_length,
                        const struct buffer_list *certs, uint8_t **cms) {
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

  EVP_PKEY *pkey = (EVP_PKEY *)crypto_key2context(key, key_length);
  if (pkey == NULL) {
    log_error("crypto_key2context fail");
    return -1;
  }

  ssize_t length =
      sign_withkey_cms(data, data_length, cert, cert_length, pkey, certs, cms);

  if (length < 0) {
    log_error("sign_withkey_eccms fail");
    EVP_PKEY_free(pkey);
    return -1;
  }

  EVP_PKEY_free(pkey);
  return length;
}

static int exatract_cms_certs(CMS_ContentInfo *cms,
                              struct buffer_list **out_certs) {
  STACK_OF(X509) *signers = CMS_get0_signers(cms);
  int length = sk_X509_num(signers);

  if (signers == NULL || !length) {
    return 0;
  }

  *out_certs = init_buffer_list();
  if (*out_certs == NULL) {
    log_error("init_buffer_list fail");
    return -1;
  }

  for (int idx = 0; idx < length; idx++) {
    const X509 *signer = sk_X509_value(signers, idx);
    uint8_t *cert = NULL;
    ssize_t cert_length = cert_to_derbuf(signer, &cert);
    if (cert_length < 0) {
      log_error("cert_to_derbuf fail");
      free_buffer_list(*out_certs);
      *out_certs = NULL;
      return -1;
    }
    if (push_buffer_list(*out_certs, cert, cert_length, 0) < 0) {
      log_error("push_buffer_list fail");
      sys_free(cert);
      free_buffer_list(*out_certs);
      *out_certs = NULL;
      return -1;
    }
  }

  return 0;
}

ssize_t crypto_verify_cms(const uint8_t *cms, const size_t cms_length,
                          const struct buffer_list *certs,
                          const struct buffer_list *store, uint8_t **data,
                          struct buffer_list **out_certs) {
  if (cms == NULL) {
    log_error("cms param is NULL");
    return -1;
  }

  if (data == NULL) {
    log_error("data param is NULL");
    return -1;
  }

  CMS_ContentInfo *content = derbuf_to_cms(cms, cms_length);
  if (content == NULL) {
    log_error("derbuf_to_cms fail");
    return -1;
  }

  STACK_OF(X509) *cert_stack = NULL;
  if (certs != NULL) {
    if ((cert_stack = get_certificate_stack(certs)) == NULL) {
      log_error("get_certificate_stack fail");
      CMS_ContentInfo_free(content);
      return -1;
    }
  }

  X509_STORE *cert_store = NULL;
  struct ptr_list *x509_store_list = NULL;
  if (store != NULL) {
    cert_store = get_certificate_store(store, &x509_store_list);

    if (cert_store == NULL) {
      log_error("get_certificate_store fail");
      sk_X509_pop_free(cert_stack, X509_free);
      CMS_ContentInfo_free(content);
      return -1;
    }
  }

  BIO *mem_data = BIO_new_ex(NULL, BIO_s_mem());
  if (mem_data == NULL) {
    log_error("BIO_new_ex fail with code=%lu", ERR_get_error());
    goto crypto_verify_cms_fail;
  }

  unsigned int flags = (cert_store == NULL) ? CMS_NO_SIGNER_CERT_VERIFY : 0;

  if (!CMS_verify(content, cert_stack, cert_store, NULL, mem_data, flags)) {
    log_error("CMS_verify fail with code=%lu", ERR_get_error());
    goto crypto_verify_cms_fail;
  }

  ssize_t length = bio_to_ptr(mem_data, data);
  if (length < 0) {
    log_error("bio_to_ptr fail");
    goto crypto_verify_cms_fail;
  }

  /* Extract the list of certs from the CMS */
  if (out_certs != NULL) {
    *out_certs = NULL;
    if (exatract_cms_certs(content, out_certs) < 0) {
      log_error("exatract_cms_certs fail");
      goto crypto_verify_cms_fail;
    }
  }

  BIO_free(mem_data);
  sk_X509_pop_free(cert_stack, X509_free);
  CMS_ContentInfo_free(content);
  free_x509_store(cert_store, x509_store_list);
  return length;

crypto_verify_cms_fail:
  BIO_free(mem_data);
  sk_X509_pop_free(cert_stack, X509_free);
  CMS_ContentInfo_free(content);
  free_x509_store(cert_store, x509_store_list);
  return -1;
}
