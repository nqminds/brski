/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the voucher structure.
 */
#ifndef VOUCHER_H
#define VOUCHER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "array.h"

/**
 *
 * module: ietf-voucher
 *
 *   yang-data voucher-artifact:
 *       +---- voucher
 *          +---- created-on                       yang:date-and-time
 *          +---- expires-on?                      yang:date-and-time
 *          +---- assertion                        enumeration
 *          +---- serial-number                    string
 *          +---- idevid-issuer?                   binary
 *          +---- pinned-domain-cert               binary
 *          +---- domain-cert-revocation-checks?   boolean
 *          +---- nonce?                           binary
 *          +---- last-renewal-date?               yang:date-and-time
 *          +-- prior-signed-voucher-request?      binary
 *          +-- proximity-registrar-cert?          binary
 *
 */

/**
 * The voucher artifact is a JSON [RFC8259] document that conforms with
 * a data model described by YANG [RFC7950], is encoded using the rules
 * defined in [RFC8259], and is signed using (by default) a CMS
 * structure [RFC5652].
 *
 * The primary purpose of a voucher is to securely convey a certificate,
 * the "pinned-domain-cert", that a pledge can use to authenticate
 * subsequent interactions.  A voucher may be useful in several
 * contexts, but the driving motivation herein is to support secure
 * bootstrapping mechanisms.  Assigning ownership is important to
 * bootstrapping mechanisms so that the pledge can authenticate the
 * network that is trying to take control of it.
 */
enum VoucherAttributes {
  /**
   * A value indicating the date this voucher was created.  This
   * node is primarily for human consumption and auditing.  Future
   * work MAY create verification requirements based on this
   * node.
   */
  ATTR_CREATED_ON = 0,

  /**
   * A value indicating when this voucher expires.  The node is
   * optional as not all pledges support expirations, such as
   * pledges lacking a reliable clock.
   *
   * If this field exists, then the pledges MUST ensure that
   * the expires-on time has not yet passed.  A pledge without
   * an accurate clock cannot meet this requirement.
   *
   * The expires-on value MUST NOT exceed the expiration date
   * of any of the listed 'pinned-domain-cert' certificates.
   */
  ATTR_EXPIRES_ON,

  /**
   * The assertion is a statement from the MASA regarding how
   * the owner was verified.  This statement enables pledges
   * to support more detailed policy checks.  Pledges MUST
   * ensure that the assertion provided is acceptable, per
   * local policy, before processing the voucher.
   */
  ATTR_ASSERTION,

  /**
   * The serial-number of the hardware.  When processing a
   * voucher, a pledge MUST ensure that its serial-number
   * matches this value.  If no match occurs, then the
   * pledge MUST NOT process this voucher.
   */
  ATTR_SERIAL_NUMBER,

  /**
   * The Authority Key Identifier OCTET STRING (as defined in
   * Section 4.2.1.1 of RFC 5280) from the pledge's IDevID
   * certificate.  Optional since some serial-numbers are
   * already unique within the scope of a MASA.
   * Inclusion of the statistically unique key identifier
   * ensures statistically unique identification of the hardware.
   * When processing a voucher, a pledge MUST ensure that its
   * IDevID Authority Key Identifier matches this value.  If no
   * match occurs, then the pledge MUST NOT process this voucher.
   *
   * When issuing a voucher, the MASA MUST ensure that this field
   * is populated for serial-numbers that are not otherwise unique
   * within the scope of the MASA.
   */
  ATTR_IDEVID_ISSUER,

  /**
   * An X.509 v3 certificate structure, as specified by RFC 5280,
   * using Distinguished Encoding Rules (DER) encoding, as defined
   * in ITU-T X.690.
   *
   * This certificate is used by a pledge to trust a Public Key
   * Infrastructure in order to verify a domain certificate
   * supplied to the pledge separately by the bootstrapping
   * protocol.  The domain certificate MUST have this certificate
   * somewhere in its chain of certificates.  This certificate
   * MAY be an end-entity certificate, including a self-signed
   * entity.
   */
  ATTR_PINNED_DOMAIN_CERT,

  /**
   * A processing instruction to the pledge that it MUST (true)
   * or MUST NOT (false) verify the revocation status for the
   * pinned domain certificate.  If this field is not set, then
   * normal PKIX behavior applies to validation of the domain
   * certificate.
   */
  ATTR_DOMAIN_CERT_REVOCATION_CHECKS,

  /**
   * A value that can be used by a pledge in some bootstrapping
   * protocols to enable anti-replay protection.  This node is
   * optional because it is not used by all bootstrapping
   * protocols.
   *
   * When present, the pledge MUST compare the provided nonce
   * value with another value that the pledge randomly generated
   * and sent to a bootstrap server in an earlier bootstrapping
   * message.  If the values do not match, then the pledge MUST
   * NOT process this voucher.
   */
  ATTR_NONCE,

  /**
   * The date that the MASA projects to be the last date it
   * will renew a voucher on.  This field is merely informative;
   * it is not processed by pledges.
   *
   * Circumstances may occur after a voucher is generated that
   * may alter a voucher's validity period.  For instance, a
   * vendor may associate validity periods with support contracts,
   * which may be terminated or extended over time.
   */
  ATTR_LAST_RENEWAL_DATE,

  /**
   * If it is necessary to change a voucher, or re-sign and
   * forward a voucher that was previously provided along a
   * protocol path, then the previously signed voucher SHOULD
   * be included in this field.
   *
   * For example, a pledge might sign a voucher-request
   * with a proximity-registrar-cert, and the registrar
   * then includes it as the prior-signed-voucher-request
   * field.  This is a simple mechanism for a chain of
   * trusted parties to change a voucher-request, while
   * maintaining the prior signature information.
   *
   * The registrar and MASA MAY examine the prior-signed
   * voucher information for the
   * purposes of policy decisions.  For example, this
   * information could be useful to a MASA to determine
   * that both the pledge and registrar agree on proximity
   * assertions.  The MASA SHOULD remove all
   * prior-signed-voucher-request information when
   * signing a voucher for imprinting so as to minimize
   * the final voucher size.
   */
  ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,

  /**
   * An X.509 v3 certificate structure, as specified by
   * RFC 5280, Section 4, encoded using the ASN.1
   * distinguished encoding rules (DER), as specified
   * in ITU X.690.
   *
   * The first certificate in the registrar TLS server
   * certificate_list sequence (the end-entity TLS
   * certificate; see RFC 8446) presented by the registrar
   * to the pledge.  This MUST be populated in a pledge's
   * voucher-re
   */
  ATTR_PROXIMITY_REGISTRAR_CERT
};

enum VoucherAssertions {
  VOUCHER_ASSERTION_NONE = 0,

  /**
   * Indicates that the ownership has been positively
   * verified by the MASA (e.g., through sales channel
   * integration).
   */
  VOUCHER_ASSERTION_VERIFIED = 1,

  /**
   * Indicates that the voucher has been issued after
   * minimal verification of ownership or control.  The
   * issuance has been logged for detection of
   * potential security issues (e.g., recipients of
   * vouchers might verify for themselves that unexpected
   * vouchers are not in the log).  This is similar to
   * unsecured trust-on-first-use principles but with the
   * logging providing a basis for detecting unexpected
   * events.
   */
  VOUCHER_ASSERTION_LOGGED = 2,

  /**
   * Indicates that the voucher has been issued after
   * the MASA verified a proximity proof provided by the
   * device and target domain.  The issuance has been logged
   * for detection of potential security issues.  This is
   * stronger than just logging, because it requires some
   * verification that the pledge and owner are
   * in communication but is still dependent on analysis of
   * the logs to detect unexpected events.
   */
  VOUCHER_ASSERTION_PROXIMITY = 3
};

struct Voucher;

/**
 * @brief Frees an allocated voucher structure
 *
 * @param[in] voucher The allocated voucher structure
 */
void free_voucher(struct Voucher *voucher);

#if __GNUC__ >= 11 // this syntax will throw an error in GCC 10 or Clang
#define __must_free_voucher                                                    \
  __attribute__((malloc(free_voucher, 1))) __must_check
#else
#define __must_free_voucher __must_check
#endif /* __GNUC__ >= 11 */

/**
 * @brief Initialises an empty voucher structure
 *
 * Caller is responsible for freeing the voucher
 *
 * @return struct Voucher* pointer to allocated voucher, NULL on failure
 */
__must_free_voucher struct Voucher *init_voucher(void);

/**
 * @brief Sets the value for a voucher bool attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The bool voucher attribute
 * @param[in] value The bool attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_bool_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const bool value);

/**
 * @brief Sets the value for a voucher time attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The time voucher attribute
 * @param[in] value The time attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_time_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const struct tm *value);

/**
 * @brief Sets the value for a voucher enum attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The enum voucher attribute
 * @param[in] value The enum attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_enum_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const int value);

/**
 * @brief Sets the value for a voucher string attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The string voucher attribute name
 * @param[in] value The string attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_str_voucher(struct Voucher *voucher,
                         const enum VoucherAttributes attr, const char *value);

/**
 * @brief Sets the value for a voucher array attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @param[in] value The array attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_array_voucher(struct Voucher *voucher,
                           const enum VoucherAttributes attr,
                           const struct BinaryArray *value);

/**
 * @brief Sets the value for a voucher attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @param[in] __VA_ARGS__ The variable list of attribute values:
 *  ATTR_CREATED_ON => struct tm *
 *  ATTR_EXPIRES_ON => struct tm *
 *  ATTR_LAST_RENEWAL_DATE => struct tm *
 *  ATTR_ASSERTION => enum VoucherAssertions
 *  ATTR_SERIAL_NUMBER => char *
 *  ATTR_IDEVID_ISSUER => struct BinaryArray *
 *  ATTR_PINNED_DOMAIN_CERT => struct BinaryArray *
 *  ATTR_NONCE => struct BinaryArray *
 *  ATTR_PRIOR_SIGNED_VOUCHER_REQUEST => struct BinaryArray *
 *  ATTR_PROXIMITY_REGISTRAR_CERT => struct BinaryArray *
 *  ATTR_DOMAIN_CERT_REVOCATION_CHECKS => bool
 * @return 0 on success, -1 on failure
 */
int set_attr_voucher(struct Voucher *voucher, const enum VoucherAttributes attr,
                     ...);

/**
 * @brief Clears a voucher attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The attribute name
 * @return 0 on success, -1 on failure
 */
int clear_attr_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr);

/**
 * @brief Checks if a voucher attribute is non empty
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The attribute name
 * @return true if non empty, false otherwise
 */
bool is_attr_voucher_nonempty(const struct Voucher *voucher,
                              const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher bool attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The bool voucher attribute
 * @return const bool* pointer to the bool value, NULL on failure
 */
const bool *get_attr_bool_voucher(const struct Voucher *voucher,
                                  const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher time attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The time voucher attribute
 * @return const struct tm * pointer to the time value, NULL on failure
 */
const struct tm *get_attr_time_voucher(struct Voucher *voucher,
                                       const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher enum attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The enum voucher attribute
 * @return const int* pointer to the enum value, NULL on failure
 */
const int *get_attr_enum_voucher(struct Voucher *voucher,
                                 const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher string attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The string voucher attribute name
 * @return const char* const* pointer to the string value, NULL on failure
 */
const char *const *get_attr_str_voucher(struct Voucher *voucher,
                                        const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher array attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @return const struct BinaryArray* pointer to the array value, NULL on
 * failure
 */
const struct BinaryArray *
get_attr_array_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr);

/**
 * @brief Serializes a voucher to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] voucher The allocated voucher structure
 * @return char* serialized voucher, NULL on failure
 */
__must_sys_free char *serialize_voucher(const struct Voucher *voucher);

/**
 * @brief Deserializes a json string buffer to a voucher structure
 *
 * Caller is responsible for freeing the voucher struct
 *
 * @param[in] json The json string buffer
 * @param[in] length The json string buffer length
 * @return struct Voucher * voucher structure, NULL on failure
 */
__must_free_voucher struct Voucher *deserialize_voucher(const uint8_t *json,
                                                        const size_t length);

/**
 * @brief Signs a voucher using CMS with an Elliptic Curve private key
 * and output to a binary buffer (DER format)
 *
 * Caller is responsible for freeing the output binary buffer
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] cert The certificate buffer (DER format) correspoding to the
 * private key
 * @param[in] key The Elliptic Curve private key buffer (DER format) of the
 * certificate
 * @param[in] certs The list of additional certificate buffers (DER format) to
 * be included in the CMS (NULL if none)
 * @return struct BinaryArray * the signed CMS structure in binary (DER
 * format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *
sign_eccms_voucher(struct Voucher *voucher, const struct BinaryArray *cert,
                   const struct BinaryArray *key,
                   const struct BinaryArrayList *certs);

/**
 * @brief Signs a voucher using CMS with a RSA private key
 * and output to binary buffer (DER format)
 *
 * Caller is responsible for freeing the output binary buffer
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] cert The certificate buffer (DER format) correspoding to the
 * private key
 * @param[in] key The RSA private key buffer (DER format) of the certificate
 * @param[in] certs The list of additional certificate buffers (DER format) to
 * be included in the CMS (NULL if none)
 * @return struct BinaryArray* the signed CMS structure in binary (DER
 * format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *
sign_rsacms_voucher(struct Voucher *voucher, const struct BinaryArray *cert,
                    const struct BinaryArray *key,
                    const struct BinaryArrayList *certs);

/**
 * @brief Signs a voucher using CMS with a private key (detected automatically)
 * and output to a binary array (DER format)
 *
 * Caller is responsible for freeing the output binary array
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] cert The certificate buffer (DER format) correspoding to the
 * private key
 * @param[in] key The private key buffer (DER format) of the certificate
 * @param[in] certs The list of additional certificate buffers (DER format) to
 * be included in the CMS (NULL if none)
 * @return struct BinaryArray* the signed CMS structure as binary array
 * (DER format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *
sign_cms_voucher(struct Voucher *voucher, const struct BinaryArray *cert,
                 const struct BinaryArray *key,
                 const struct BinaryArrayList *certs);

/**
 * @brief Verifies a CMS binary buffer and extracts the voucher structure, and
 * the list of included certificates
 *
 * Caller is responsible for freeing the voucher and output certs buffer
 *
 * @param[in] cms The CMS binary buffer (DER format)
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @param[in] store The list of trusted certificate for store (DER format)
 * @param[out] out_certs The output list of certs (NULL for empty) from the CMS
 * structure
 * @return struct Voucher * the verified voucher, NULL on failure
 */
__must_free_voucher struct Voucher *verify_cms_voucher(
    const struct BinaryArray *cms, const struct BinaryArrayList *certs,
    const struct BinaryArrayList *store, struct BinaryArrayList **out_certs);

/**
 * @brief Signs a pledge-voucher request using CMS with a private key (type
 * detected automatically) and output as a binary array (DER format)
 *
 * Caller is responsible for freeing the output binary array
 *
 * @param[in] created_on Time when the pledge is created
 * @param[in] serial_number The serial number string of the pledge
 * @param[in] nonce Random/pseudo-random nonce (NULL for empty)
 * @param[in] registrar_tls_cert The first certificate in the TLS server
 * "certificate_list" sequence presented by the registrar to the pledge (DER
 * format)
 * @param[in] pledge_sign_cert The certificate buffer (DER format) corresponding
 * to the signing private key
 * @param[in] pledge_sign_key The private key buffer (DER format) for signing
 * the pledge-voucher request
 * @param[in] additional_pledge_certs The list of additional pledge certificates
 * (DER format) to append to CMS (NULL for empty)
 * @return struct BinaryArray* the signed pledge-voucher CMS structure as
 * binary array (DER format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *sign_pledge_voucher_request(
    const struct tm *created_on, const char *serial_number,
    const struct BinaryArray *nonce,
    const struct BinaryArray *registrar_tls_cert,
    const struct BinaryArray *pledge_sign_cert,
    const struct BinaryArray *pledge_sign_key,
    const struct BinaryArrayList *additional_pledge_certs);

/**
 * @brief Signs a voucher request using CMS with a private key (type detected
 * automatically) and output to base64 (PEM format)
 *
 * Caller is responsible for freeing the output binary array
 *
 * @param[in] pledge_voucher_request_cms The signed pledge-voucher request CMS
 * structure as binary array (DER format)
 * @param[in] created_on Time when the voucher request is created
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] idevid_issuer The idevid issuer from the idevid certificate
 * @param[in] registrar_tls_cert The first certificate in the TLS server
 * "certificate_list" sequence presented by the registrar to the pledge (DER
 * format)
 * @param[in] registrar_sign_cert The certificate buffer (
 * DER format) corresponding to the signing private key
 * @param[in] registrar_sign_key The private key buffer (DER format) for signing
 * the voucher request
 * @param[in] pledge_verify_certs The list of intermediate certificate buffers
 * (DER format) to verify the pledge-voucher request (NULL for empty)
 * @param[in] pledge_verify_store The list of trusted certificate buffers (DER
 * format) to verify the pledge-voucher request (NULL for empty)
 * @param[in] additional_registrar_certs The list of additional registrar
 * certificate buffers (DER format) to append to CMS (NULL for empty)
 * @return struct BinaryArray* the signed CMS structure as binary array
 * (DER format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *
sign_voucher_request(const struct BinaryArray *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct BinaryArray *idevid_issuer,
                     const struct BinaryArray *registrar_tls_cert,
                     const struct BinaryArray *registrar_sign_cert,
                     const struct BinaryArray *registrar_sign_key,
                     const struct BinaryArrayList *pledge_verify_certs,
                     const struct BinaryArrayList *pledge_verify_store,
                     const struct BinaryArrayList *additional_registrar_certs);

/**
 * @brief Callback function definition to find a pledge serial number in a
 * user defined database and a output a pinned domain certificate (DER format).
 *
 * Caller is responsible for freeing output pinned domain certificate
 *
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] additional_registrar_certs The list of additional registrar
 * certificates (DER format) appended to the voucher request CMS
 * @param[in] user_ctx The callback function user context
 * @param[out] voucher_req_fn The output pinned domain certificate (DER
 * format) for the pledge
 * @return 0 on success, -1 on failure
 */
typedef int (*voucher_req_fn)(
    const char *serial_number,
    const struct BinaryArrayList *additional_registrar_certs, void *user_ctx,
    struct BinaryArray *pinned_domain_cert);

/**
 * @brief Signs a MASA voucher request using CMS with a private key
 * (type detected automatically) and output as binary array (DER format)
 *
 * Caller is responsible for freeing the output binary array
 *
 * @param[in] voucher_request_cms The signed pledge voucher request CMS
 * structure as binary array (DER format)
 * @param[in] expires_on Time when the new voucher will expire
 * @param[in] voucher_req_fn The callback function to output pinned domain
 * certificate (DER format)
 * @param[in] user_ctx The callback function user context (NULL for empty)
 * @param[in] masa_sign_cert The certificate buffer (DER format) corresponding
 * to the signing private key
 * @param[in] masa_sign_key The private key buffer (DER format) for signing the
 * MASA voucher request
 * @param[in] registrar_verify_certs The list of intermediate certificate
 * buffers (DER format) to verify the voucher request from registrar (NULL for
 * empty)
 * @param[in] registrar_verify_store The list of trusted certificate buffers
 * (DER format) to verify the voucher request from registrar (NULL for empty)
 * @param[in] pledge_verify_certs The list of intermediate certificate buffers
 * (DER format) to verify the pledge-voucher request (NULL for empty)
 * @param[in] pledge_verify_store The list of trusted certificate buffers (DER
 * format) to verify the pledge-voucher request (NULL for empty)
 * @param[in] additional_masa_certs The list of additional MASA
 * certificate buffers (DER format) to append to CMS (NULL for empty)
 * @return struct BinaryArray* the signed CMS structure as binary array
 * (DER format), NULL on failure
 */
__must_free_binary_array struct BinaryArray *sign_masa_pledge_voucher(
    const struct BinaryArray *voucher_request_cms, const struct tm *expires_on,
    voucher_req_fn cb, void *user_ctx, const struct BinaryArray *masa_sign_cert,
    const struct BinaryArray *masa_sign_key,
    const struct BinaryArrayList *registrar_verify_certs,
    const struct BinaryArrayList *registrar_verify_store,
    const struct BinaryArrayList *pledge_verify_certs,
    const struct BinaryArrayList *pledge_verify_store,
    const struct BinaryArrayList *additional_masa_certs);

/**
 * @brief Verifies a MASA pledge voucher and outputs a pinned domain certificate
 * (DER format)
 *
 * Caller is reponsible for freeing the output certificate list
 *
 * @param[in] masa_pledge_voucher_cms The signed MASA pledge voucher CMS
 * structure as binarry (DER format)
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] nonce Random/pseudo-random nonce from the pledge voucher request
 * (NULL for empty)
 * @param[in] registrar_tls_cert The first certificate in the TLS server
 * "certificate_list" sequence presented by the registrar to the pledge (DER
 * format)
 * @param[in] domain_store The list of trusted certificate buffers (DER
 * format) to verify the pinned domain certificate (NULL for empty)
 * @param[in] pledge_verify_certs The list of intermediate certificate buffers
 * (DER format) to verify the MASA pledge voucher (NULL for empty)
 * @param[in] pledge_verify_store The list of trusted certificate buffers
 * (DER format) to verify the MASA pledge voucher (NULL for empty)
 * @param[out] pledge_out_certs The list of output certificate buffers (NULL for
 * empty) from the MASA pledge CMS structure
 * @param[out] pinned_domain_cert The output pinned domain certificate buffer
 * (DER format)
 * @return 0 on success, -1 on failure
 */
int verify_masa_pledge_voucher(
    const struct BinaryArray *masa_pledge_voucher_cms,
    const char *serial_number, const struct BinaryArray *nonce,
    const struct BinaryArray *registrar_tls_cert,
    const struct BinaryArrayList *domain_store,
    const struct BinaryArrayList *pledge_verify_certs,
    const struct BinaryArrayList *pledge_verify_store,
    struct BinaryArrayList **pledge_out_certs,
    struct BinaryArray *const pinned_domain_cert);
#endif
