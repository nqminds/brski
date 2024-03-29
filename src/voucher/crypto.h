/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the crypto types.
 */
#ifndef VOUCHER_CRYPTO_H
#define VOUCHER_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "array.h"

/* The generalized context for a private key */
typedef void *CRYPTO_KEY;

/* The generalized context for a certificate */
typedef void *CRYPTO_CERT;

struct crypto_cert_meta {
  uint64_t serial_number;
  /**
   * Certificate validity "Not Before" offset.
   *
   * This is the number of seconds after the current time for the certificate
   * to start being valid.
   */
  long not_before;
  /**
   * Certificate validity "Not After" offset.
   *
   * This is the number of seconds after the current for the certificate to
   * stop being valid (aka expire).
   *
   * Either this or #not_after_absolute must be set (not both).
   */
  long not_after;
  /**
   * Optional Certificate validity "Not After" string.
   *
   * This must be an ASN.1 GENERALIZEDTIME string, e.g. in format
   * `YYYYMMDDHH[MM[SS[.fff]]]Z`.
   *
   * Either this or #not_after must be set (not both).

   * Set to `"99991231235959Z"` for a [long-lived pledge certificate][1]
   * [1]:
   https://www.rfc-editor.org/rfc/rfc8995.html#name-infinite-lifetime-of-idevid
   */
  const char *not_after_absolute;

  /*
    Decoded key/value pairs:
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
 * @brief Fills in an array with random bytes
 *
 * @param[in] buf The input array
 * @return 0 on success, -1 on failure
 */
int crypto_getrand(struct BinaryArray *buf);

/**
 * @brief Makes a copy of the certificate structire
 *
 * @param[in] cert The input certificate structure
 * @return CRYPTO_CERT certificate context, NULL on failure
 */
CRYPTO_CERT crypto_copycert(CRYPTO_CERT cert);

/**
 * @brief Convert a cert context to a DER binary array
 *
 * Caller is responsible for freeing the binary array
 *
 * @param[in] cert The input certificate structure
 * @return struct BinaryArray * the output DER binary array, NULL on failure
 */
struct BinaryArray *crypto_cert2buf(CRYPTO_CERT cert);

/**
 * @brief Parses a certificate
 *
 * @param[in] cert The input certificate structure
 * @param[out] meta The output certificate metadata structrure
 * @return 0 on success, -1 on failure
 */
int crypto_getcert_meta(CRYPTO_CERT cert, struct crypto_cert_meta *meta);

/**
 * @brief Returns the certificater issuer array
 *
 * Caller is responsible for freeing the output array
 *
 * @param[in] cert The input certificate structure
 * @return struct BinaryArray * the output certificate issuer array, NULL on
 * failure
 */
__must_free_binary_array struct BinaryArray *
crypto_getcert_issuer(CRYPTO_CERT cert);

/**
 * @brief Returns the certificater serial number from the subject
 *
 * @param[in] meta The input certificate metadata
 * @return The serial number string or NULL on failure
 */
char *crypto_getcert_serial(struct crypto_cert_meta *meta);

/**
 * @brief Generate a private RSA key for a given number of bits
 * The generated key is binary (DER) raw format
 *
 * Caller is responsible for freeing the key binary array
 *
 * @param[in] bits Number of key bits for RSA
 * @return struct BinaryArray * the key binary array, NULL on failure
 */
__must_free_binary_array struct BinaryArray *
crypto_generate_rsakey(const int bits);

/**
 * @brief Generate a private Elliptic Curve key of the type prime256v1
 * The generated key is binary (DER) raw format
 *
 * Caller is responsible for freeing the key buffer
 *
 * @param[out] key The output key buffer (DER format)
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_eckey(uint8_t **key);

/**
 * @brief Frees a private key context
 *
 * @param[in] ctx The key context
 */
void crypto_free_keycontext(CRYPTO_KEY ctx);

/**
 * @brief Frees a certificate context
 *
 * @param[in] ctx The certificate context
 */
void crypto_free_certcontext(CRYPTO_KEY cert);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_crypto_free_keycontext                                          \
  __attribute__((malloc(crypto_free_keycontext, 1))) __must_check
#else
#define __must_crypto_free_keycontext __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Maps a private Elliptic Curve key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer (DER format)
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_eckey2context(const uint8_t *key, const size_t length);

/**
 * @brief Maps a private RSA key to a key context
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer (DER format)
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_rsakey2context(const uint8_t *key, const size_t length);

/**
 * @brief Maps a private key buffer to a key context
 * The function tries to detect the key type automatically
 *
 * Caller is responsible for freeing the key context
 *
 * @param[in] key The input key buffer (DER format)
 * @param[in] length The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_key2context(const uint8_t *key, const size_t length);

/**
 * @brief Maps a certificate buffer to a certificate context
 *
 * Caller is responsible for freeing the certificate context
 *
 * @param[in] key The input certificate buffer (DER format)
 * @param[in] length The certificate buffer length
 * @return CRYPTO_CERT certificate context, NULL on failure
 */
CRYPTO_CERT crypto_cert2context(const uint8_t *cert, const size_t length);

/**
 * @brief Generate a certificate and self sign with a Elliptic Curve private key
 * using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param[in] meta The certificate metadata
 * @param[in] key The Elliptic Curve private/public key buffer (DER format)
 * @param[in] key_length The private key buffer length
 * @param[out] cert The output certificate buffer (DER format)
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_eccert(const struct crypto_cert_meta *meta,
                               const uint8_t *key, const size_t key_length,
                               uint8_t **cert);

/**
 * @brief Generate a certificate and self signs with a RSA private key (DER
 * format) using sha256
 *
 * Caller is responsible for freeing the cert buffer
 *
 * @param[in] meta The certificate metadata
 * @param[in] key The RSA private/public key buffer (DER format)
 * @param[in] key_length The private key buffer length
 * @param[out] cert The output certificate buffer (DER format)
 * @return ssize_t the size of the certificate buffer, -1 on failure
 */
ssize_t crypto_generate_rsacert(const struct crypto_cert_meta *meta,
                                const uint8_t *key, const size_t key_length,
                                uint8_t **cert);

/**
 * @brief Signs a certificate buffer with a private key (DER format).
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
 * @brief Verifies a certificate buffer (DER format)
 *
 * @param[in] cert The certificate buffer (DER format) to be verified
 * @param[in] cert_length The certificate buffer length
 * @param[in] certs The list of certificate buffers (DER format) to verify the
 * certificate
 * @param[in] store The list of trusted certificate store buffers (DER format)
 * to verify the certificate
 * @return int 0 if certificate is signed by the certs/store, -1 on failure
 */
int crypto_verify_cert(const uint8_t *cert, const size_t cert_length,
                       const struct BinaryArrayList *certs,
                       const struct BinaryArrayList *store);
/**
 * @brief Signs a buffer using CMS for an Elliptic Curve private key (DER
 * format)
 *
 * Caller is responsible for freeing the CMS buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer (DER format) for signing private key
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The signing Elliptic Curve private key buffer (DER format) of
 * the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @param[out] cms The output CMS buffer (DER format)
 * @return ssize_t the size of the CMS buffer, -1 on failure
 */
ssize_t crypto_sign_eccms(const uint8_t *data, const size_t data_length,
                          const uint8_t *cert, const size_t cert_length,
                          const uint8_t *key, const size_t key_length,
                          const struct BinaryArrayList *certs, uint8_t **cms);

/**
 * @brief Signs a buffer using CMS for a private key (DER format).
 * The private key type is detected automatically.
 *
 * Caller is responsible for freeing the CMS buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer (DER format) for the signing private
 * key
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The signing Elliptic Curve private key buffer (DER format) of
 * the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @param[out] cms The output CMS buffer (DER format)
 * @return ssize_t the size of the CMS buffer, -1 on failure
 */
ssize_t crypto_sign_cms(const uint8_t *data, const size_t data_length,
                        const uint8_t *cert, const size_t cert_length,
                        const uint8_t *key, const size_t key_length,
                        const struct BinaryArrayList *certs, uint8_t **cms);

/**
 * @brief Signs a buffer using CMS for an RSA private key (DER format)
 *
 * Caller is responsible for freeing the CMS buffer
 *
 * @param[in] data The data buffer to be signed
 * @param[in] data_length The data buffer length
 * @param[in] cert The certificate buffer (DER format) for the signing private
 * key
 * @param[in] cert_length The certificate buffer length
 * @param[in] key The RSA private key buffer (DER format) of the certificate
 * @param[in] key_length The length of the private key buffer
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @param[out] cms The output CMS buffer (DER format)
 * @return ssize_t the size of the CMS buffer, -1 on failure
 */
ssize_t crypto_sign_rsacms(const uint8_t *data, const size_t data_length,
                           const uint8_t *cert, const size_t cert_length,
                           const uint8_t *key, const size_t key_length,
                           const struct BinaryArrayList *certs, uint8_t **cms);

/**
 * @brief Verifies a CMS buffer (DER format) and extract the data
 * buffer
 *
 * Caller is responsible for freeing the data buffer and output certs buffer
 *
 * @param[in] cms The CMS binary array (DER format) to be verified
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @param[in] store The list of trusted certificate for store (DER format)
 * @param[out] data The output data buffer
 * @param[out] out_certs The list of certificate buffers (DER format) from the
 * CMS structure (NULL for empty)
 * @return ssize_t the size of the data buffer, -1 on failure
 */
ssize_t crypto_verify_cms(const struct BinaryArray *cms,
                          const struct BinaryArrayList *certs,
                          const struct BinaryArrayList *store, uint8_t **data,
                          struct BinaryArrayList **out_certs);

/**
 * @brief Convert a x509 PEM file to a DER binary array
 *
 * Caller is responsible for freeing the binary array
 *
 * @param[in] filename The x509 PEM file path
 * @return struct BinaryArray * the output DER binary array, NULL on failure
 */
struct BinaryArray *file_to_x509buf(const char *filename);

/**
 * @brief Convert a key PEM file to a DER binary array
 *
 * Caller is responsible for freeing the binary array
 *
 * @param[in] filename The key PEM file path
 * @return struct BinaryArray * the output DER binary array, NULL on failure
 */
struct BinaryArray *file_to_keybuf(const char *filename);

/**
 * @brief Saves a cms binary array to a SMIME file
 *
 * @param[in] cms The cms binary array (DER format)
 * @param[in] filename The output file path
 * @return 0 on success, -1 on failure
 */
int cmsbuf_to_file(const struct BinaryArray *cms, const char *filename);

/**
 * @brief Saves a certificate binary array to a PEM file
 *
 * @param[in] cert The certificate binary array (DER format)
 * @param[in] filename The output file path
 * @return 0 on success, -1 on failure
 */
int certbuf_to_file(const struct BinaryArray *cert, const char *filename);

/**
 * @brief Saves a private key binary array to a PEM file
 *
 * @param[in] cert The private key binary array (DER format)
 * @param[in] filename The output file path
 * @return 0 on success, -1 on failure
 */
int keybuf_to_file(const struct BinaryArray *key, const char *filename);
#endif
