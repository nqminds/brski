/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the voucher structure.
 */
#ifndef VOUCHER_IMPL_H
#define VOUCHER_IMPL_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "voucher.h"

struct Voucher {
  /* ATTR_CREATED_ON */
  struct tm created_on;

  /* ATTR_EXPIRES_ON */
  struct tm expires_on;

  /* ATTR_ASSERTION */
  enum VoucherAssertions assertion;

  /* ATTR_SERIAL_NUMBER */
  char *serial_number;

  /* ATTR_IDEVID_ISSUER */
  struct VoucherBinaryArray idevid_issuer;

  /* ATTR_PINNED_DOMAIN_CERT */
  struct VoucherBinaryArray pinned_domain_cert;

  /* ATTR_DOMAIN_CERT_REVOCATION_CHECKS */
  bool domain_cert_revocation_checks;

  /* ATTR_NONCE */
  struct VoucherBinaryArray nonce;

  /* ATTR_LAST_RENEWAL_DATE */
  struct tm last_renewal_date;

  /* ATTR_PRIOR_SIGNED_VOUCHER_REQUEST */
  struct VoucherBinaryArray prior_signed_voucher_request;

  /* ATTR_PROXIMITY_REGISTRAR_CERT */
  struct VoucherBinaryArray proximity_registrar_cert;
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

#define VOUCHER_ASSERTION_NAMES                                                \
  { NULL, "verified", "logged", "proximity" }

#endif