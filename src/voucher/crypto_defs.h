/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the crypto types.
 */
#ifndef CRYPTO_DEFS_H
#define CRYPTO_DEFS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "list.h"

/* The generalized context for a private key */
typedef void *CRYPTO_KEY;

/* The generalized context for a certificate */
typedef void *CRYPTO_CERT;

struct crypto_cert_meta {
  uint64_t serial_number;
  long not_before;
  long not_after;

  /*
    Example key/value pairs:
    [C]=US,
    [ST]=State or Province,
    [L]=locality name,
    [O]=orhanization name,
    [OU]=org unit,
    [CN]=common name,
    [emailAddress]=bob@example.com,
    [serialNumber]=1234,
    [SN]=surname,
    [GN]=given name,
    [GN]=name given
  */
  struct keyvalue_list *issuer;
  struct keyvalue_list *subject;
};

/* Types of certificate to be used in certificate store */
enum CRYPTO_CERTIFICATE_TYPE {
  /* A valid certificate */
  CRYPTO_CERTIFICATE_VALID = 0,
  /* A certificate revocation type */
  CRYPTO_CERTIFICATE_CRL,
};

/**
 * @brief Generate a private RSA key for a given number of bits
 * The generated key is binary (DER) raw format
 *
 * Caller is responsible for freeing the key buffer
 *
 * @param bits[in] Number of key bits for RSA
 * @param key[out] The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_rsakey(int bits, uint8_t **key);

/**
 * @brief Generate a private EC key of the type prime256v1
 * The generated key is binary (DER) raw format
 *
 * Caller is responsible for freeing the key buffer
 *
 * @param key[out] The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_eckey(uint8_t **key);

/**
 * @brief Maps a private EC key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param key[in] The input key buffer
 * @param length[in] The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_eckey2context(const uint8_t *key, size_t length);

/**
 * @brief Maps a private RSA key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param key[in] The input key buffer
 * @param length[in] The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_rsakey2context(const uint8_t *key, size_t length);

/**
 * @brief Frees a private key context
 *
 * @param ctx[in] The key context
 */
void crypto_free_keycontext(CRYPTO_KEY ctx);

/**
 * @brief Generate a certificate and sign with a EC private key
 * using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param meta[in] The certificate metadata
 * @param key[in] The EC private key buffer
 * @param key_length[in] The private key buffer length
 * @param cert[out] The output certificate buffer
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_eccert(struct crypto_cert_meta *meta, uint8_t *key,
                               size_t key_length, uint8_t **cert);

/**
 * @brief Generate a certificate and sign with a RSA private key
 * using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param meta[in] The certificate metadata
 * @param key[in] The RSA private key buffer
 * @param key_length[in] The private key buffer length
 * @param cert[out] The output certificate buffer
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_rsacert(struct crypto_cert_meta *meta, uint8_t *key,
                                size_t key_length, uint8_t **cert);

/**
 * @brief Signs a buffer using CMS for an EC private key
 *
 * Caller is responsible for freeing the cms buffer
 *
 * @param data[in] The data buffer to be signed
 * @param data_length[in] The data buffer length
 * @param cert[in] The certificate buffer for signing
 * @param cert_length[in] The certificate buffer length
 * @param key[in] The EC private key buffer of the certificate
 * @param key_length[in] The length of the private key buffer
 * @param certs[in] The list of additional certificate buffers
 * @param cms[out] The output cms buffer
 * @return ssize_t the size of the cms buffer, -1 on failure
 */
ssize_t crypto_sign_eccms(uint8_t *data, size_t data_length, uint8_t *cert,
                          size_t cert_length, uint8_t *key, size_t key_length,
                          struct buffer_list *certs, uint8_t **cms);

/**
 * @brief Signs a buffer using CMS for an RSA private key
 *
 * Caller is responsible for freeing the cms buffer
 *
 * @param data[in] The data buffer to be signed
 * @param data_length[in] The data buffer length
 * @param cert[in] The certificate buffer for signing
 * @param cert_length[in] The certificate buffer length
 * @param key[in] The RSA private key buffer of the certificate
 * @param key_length[in] The length of the private key buffer
 * @param certs[in] The list of additional certificate buffers
 * @param cms[out] The output cms buffer
 * @return ssize_t the size of the cms buffer, -1 on failure
 */
ssize_t crypto_sign_rsacms(uint8_t *data, size_t data_length, uint8_t *cert,
                           size_t cert_length, uint8_t *key, size_t key_length,
                           struct buffer_list *certs, uint8_t **cms);

/**
 * @brief Verifies a CMS buffer and extract the data
 * buffer
 *
 * Caller is responsible for freeing the data buffer
 *
 * @param cms[in] The cms buffer to be verified
 * @param cms_length[in] The cms buffer length
 * @param certs[in] The list of additional certificate buffers
 * @param store[in] The list of trusted certificate for store
 * @param data[out] The output data buffer
 * @return ssize_t the size of the data buffer, -1 on failure
 */
ssize_t crypto_verify_cms(uint8_t *cms, size_t cms_length,
                          struct buffer_list *certs, struct buffer_list *store, uint8_t **data);

#endif
