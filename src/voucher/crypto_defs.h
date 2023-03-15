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

  char *basic_constraints;
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
 * @param[in] bits Number of key bits for RSA
 * @param[out] key The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_rsakey(const int bits, uint8_t **key);

/**
 * @brief Generate a private Elliptic Curve key of the type prime256v1
 * The generated key is binary (DER) raw format
 *
 * Caller is responsible for freeing the key buffer
 *
 * @param[out] key The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_eckey(uint8_t **key);

/**
 * @brief Maps a private Elliptic Curve key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_eckey2context(const uint8_t *key, const size_t length);

/**
 * @brief Maps a private RSA key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_rsakey2context(const uint8_t *key, const size_t length);

/**
 * @brief Maps a private key to a key context
 * The function tries to detect the key type automatically
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_key2context(const uint8_t *key, const size_t length);

/**
 * @brief Frees a private key context
 *
 * @param[in] ctx The key context
 */
void crypto_free_keycontext(CRYPTO_KEY ctx);

/**
 * @brief Generate a certificate and self sign with a Elliptic Curve private key
 * using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param[in] meta The certificate metadata
 * @param[in] key The Elliptic Curve private/public key buffer
 * @param[in] key_length The private key buffer length
 * @param[out] cert The output certificate buffer
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_eccert(const struct crypto_cert_meta *meta,
                               const uint8_t *key, const size_t key_length,
                               uint8_t **cert);

/**
 * @brief Generate a certificate and self sign with a RSA private key
 * using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param[in] meta The certificate metadata
 * @param[in] key The RSA private/public key buffer
 * @param[in] key_length The private key buffer length
 * @param[out] cert The output certificate buffer
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_rsacert(const struct crypto_cert_meta *meta,
                                const uint8_t *key, const size_t key_length,
                                uint8_t **cert);

/**
 * @brief Signs a certificate with a private key.
 * The private key type is detected automatically. The signature is sha256.
 *
 * Caller is responsible for freeing the output certificate
 *
 * @param[in] sign_key The private signing key buffer (DER format)
 * @param[in] sign_key_length The private signing key buffer length
 * @param[in] ca_cert The CA or intermediate certificate buffer (DER format)
 * @param[in] ca_cert_length The CA or intermediate certificate buffer length
 * @param[in] cert_length The certificate buffer length
 * @param[out] cert The input and signed certificate buffer (DER format)
 * @return ssize_t the size of the signed certificate buffer, -1 on failure
 */
ssize_t crypto_sign_cert(const uint8_t *sign_key, const size_t sign_key_length,
                         const uint8_t *ca_cert, const size_t ca_cert_length,
                         const size_t cert_length, uint8_t **cert);

/**
 * @brief Verifies a certificate
 *
 * @param[in] cert The certificate buffer (DER format) to be verified
 * @param[in] cert_length The certificate buffer length
 * @param[in] certs The list of certificate buffers to verify the certificate
 * @param[in] store The list of trusted certificate store to verify the
 * certificate
 * @return int 0 if certificate is signed by the certs/store, -1 on failure
 */
int crypto_verify_cert(const uint8_t *cert, const size_t cert_length,
                       const struct buffer_list *certs,
                       const struct buffer_list *store);
/**
 * @brief Signs a buffer using CMS for an Elliptic Curve private key
 *
 * Caller is responsible for freeing the cms buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer for signing
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The Elliptic Curve private key buffer of the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers
 * @param[out] cms The output cms buffer
 * @return ssize_t the size of the cms buffer, -1 on failure
 */
ssize_t crypto_sign_eccms(const uint8_t *data, const size_t data_length,
                          const uint8_t *cert, const size_t cert_length,
                          const uint8_t *key, const size_t key_length,
                          const struct buffer_list *certs, uint8_t **cms);

/**
 * @brief Signs a buffer using CMS for a private key.
 * The private key type is detected automatically.
 *
 * Caller is responsible for freeing the cms buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer for signing
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The Elliptic Curve private key buffer of the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers
 * @param[out] cms The output cms buffer
 * @return ssize_t the size of the cms buffer, -1 on failure
 */
ssize_t crypto_sign_cms(const uint8_t *data, const size_t data_length,
                        const uint8_t *cert, const size_t cert_length,
                        const uint8_t *key, const size_t key_length,
                        const struct buffer_list *certs, uint8_t **cms);

/**
 * @brief Signs a buffer using CMS for an RSA private key
 *
 * Caller is responsible for freeing the cms buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer for signing
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The RSA private key buffer of the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers
 * @param[out] cms The output cms buffer
 * @return ssize_t the size of the cms buffer, -1 on failure
 */
ssize_t crypto_sign_rsacms(const uint8_t *data, const size_t data_length,
                           const uint8_t *cert, const size_t cert_length,
                           const uint8_t *key, const size_t key_length,
                           const struct buffer_list *certs, uint8_t **cms);

/**
 * @brief Verifies a CMS buffer and extract the data
 * buffer
 *
 * Caller is responsible for freeing the data buffer and output certs buffer
 *
 * @param[in] cms The cms buffer to be verified
 * @param[in] cms_length The cms buffer length
 * @param[in] certs The list of additional certificate buffers
 * @param[in] store The list of trusted certificate for store
 * @param[out] data The output data buffer
 * @param[out] out_certs The list of certs from the cms structure if non NULL
 * @return ssize_t the size of the data buffer, -1 on failure
 */
ssize_t crypto_verify_cms(const uint8_t *cms, const size_t cms_length,
                          const struct buffer_list *certs,
                          const struct buffer_list *store, uint8_t **data,
                          struct buffer_list **out_certs);

void x509_to_tmpfile(const uint8_t *cert, const size_t length,
                     const char *filename);
#endif
