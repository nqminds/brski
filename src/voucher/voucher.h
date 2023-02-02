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
 *
 */
#define CREATED_ON_NAME "created-on"
#define EXPIRES_ON_NAME "expires-on"
#define ASSERTION_NAME "assertion"
#define SERIAL_NUMBER_NAME "serial-number"
#define IDEVID_ISSUER_NAME "idevid-issuer"
#define PINNED_DOMAIN_CERT_NAME "pinned-domain-cert"
#define DOMAIN_CERT_REVOCATION_CHECKS_NAME "domain-cert-revocation-checks"
#define NONCE_NAME "nonce"
#define LAST_RENEWAL_DATE_NAME "last-renewal-date"

enum VoucherAssertions {
  /**
   * Indicates that the ownership has been positively
   * verified by the MASA (e.g., through sales channel
   * integration).
   */
  VOUCHER_ASSERTION_VERIFIED = 0,
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
  VOUCHER_ASSERTION_LOGGED = 1,

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
  VOUCHER_ASSERTION_PROXIMITY = 2
};

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
  time_t created_on;

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
  time_t expires_on;

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
  time_t last_renewal_date;
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
 * @param[in] name The bool attribute name
 * @param[in] value The bool attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_bool_voucher(struct Voucher *voucher, char *name, bool value);

/**
 * @brief Sets the value for a voucher time attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] name The time attribute name
 * @param[in] value The time attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_time_voucher(struct Voucher *voucher, char *name, time_t value);

/**
 * @brief Sets the value for a voucher enum attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] name The enum attribute name
 * @param[in] value The enum attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_enum_voucher(struct Voucher *voucher, char *name, int value);

/**
 * @brief Sets the value for a voucher string attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] name The string attribute name
 * @param[in] value The string attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_str_voucher(struct Voucher *voucher, char *name, char *value);

/**
 * @brief Sets the value for a voucher array attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] name The array attribute name
 * @param[in] value The array attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_array_voucher(struct Voucher *voucher, char *name, struct VoucherBinaryArray *value);

#endif
