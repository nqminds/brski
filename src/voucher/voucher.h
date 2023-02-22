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

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "crypto_defs.h"

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
enum VoucherAttributes {
  ATTR_CREATED_ON = 0,
  ATTR_EXPIRES_ON,
  ATTR_ASSERTION,
  ATTR_SERIAL_NUMBER,
  ATTR_IDEVID_ISSUER,
  ATTR_PINNED_DOMAIN_CERT,
  ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
  ATTR_NONCE,
  ATTR_LAST_RENEWAL_DATE,
  ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
  ATTR_PROXIMITY_REGISTRAR_CERT
};

#define VOUCHER_ROOT_NAME "ietf-voucher:voucher"
#define VOUCHER_REQUEST_ROOT_NAME "ietf-voucher-request:voucher"

#define VOUCHER_ATTRIBUTE_NAMES                                                \
  {                                                                            \
    "created-on", "expires-on", "assertion", "serial-number", "idevid-issuer", \
        "pinned-domain-cert", "domain-cert-revocation-checks", "nonce",        \
        "last-renewal-date", "prior-signed-voucher-request",                   \
        "proximity-registrar-cert"                                             \
  }

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

#define VOUCHER_ASSERTION_NAMES                                                \
  { NULL, "verified", "logged", "proximity" }

struct VoucherBinaryArray {
  uint8_t *array;
  size_t length;
};

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
struct Voucher {
  /**
   * A value indicating the date this voucher was created.  This
   * node is primarily for human consumption and auditing.  Future
   * work MAY create verification requirements based on this
   * node.
   */
  struct tm created_on;

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
  struct tm expires_on;

  /**
   * The assertion is a statement from the MASA regarding how
   * the owner was verified.  This statement enables pledges
   * to support more detailed policy checks.  Pledges MUST
   * ensure that the assertion provided is acceptable, per
   * local policy, before processing the voucher.
   */
  enum VoucherAssertions assertion;

  /**
   * The serial-number of the hardware.  When processing a
   * voucher, a pledge MUST ensure that its serial-number
   * matches this value.  If no match occurs, then the
   * pledge MUST NOT process this voucher.
   */
  char *serial_number;

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
  struct VoucherBinaryArray idevid_issuer;

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
  struct VoucherBinaryArray pinned_domain_cert;

  /**
   * A processing instruction to the pledge that it MUST (true)
   * or MUST NOT (false) verify the revocation status for the
   * pinned domain certificate.  If this field is not set, then
   * normal PKIX behavior applies to validation of the domain
   * certificate.
   */
  bool domain_cert_revocation_checks;

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
  struct VoucherBinaryArray nonce;

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
  struct tm last_renewal_date;

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
  struct VoucherBinaryArray prior_signed_voucher_request;

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
  struct VoucherBinaryArray proximity_registrar_cert;
};

/**
 * @brief Initialises an empty voucher structure
 *
 * @return struct Voucher* pointer to allocated voucher, NULL on failure
 */
struct Voucher *init_voucher(void);

/**
 * @brief Frees an allocated voucher structure
 *
 * @param[in] voucher The allocated voucher structure
 */
void free_voucher(struct Voucher *voucher);

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
                           const struct VoucherBinaryArray *value);

/**
 * @brief Sets the value for a voucher attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @param[in] __VA_ARGS__ The list of attribute values
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
 * @brief Serializes a voucher to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] voucher The allocated voucher structure
 * @return char* serialized voucher, NULL on failure
 */
char *serialize_voucher(const struct Voucher *voucher);

/**
 * @brief Deserializes a json string to a voucher
 *
 * Caller is responsible for freeing the voucher struct
 *
 * @param[in] json The json string
 * @return struct Voucher * voucher, NULL on failure
 */
struct Voucher *deserialize_voucher(const char *json);
#endif
