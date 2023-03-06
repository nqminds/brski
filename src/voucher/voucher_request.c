/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the voucher request structure.
 */

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "../utils/os.h"
#include "serialize.h"
#include "voucher.h"
#include "voucher_request.h"

char *sign_pledge_voucher_request(
    const struct tm *created_on, const struct VoucherBinaryArray *nonce,
    const struct VoucherBinaryArray *proximity_registrar_cert,
    const char *serial_number, const struct VoucherBinaryArray *sign_cert,
    const struct VoucherBinaryArray *sign_key,
    const struct buffer_list *pledge_certs) {
  struct Voucher *voucher = init_voucher();
  if (voucher == NULL) {
    log_error("init_voucher fail");
    return NULL;
  }

  /* Pledges that have a real-time clock are RECOMMENDED to populate this field
   * with the current date and time in yang:date-and-time format. This provides
   * additional information to the MASA. Pledges that have no real-time clocks
   * MAY omit this field. */
  if (set_attr_voucher(voucher, ATTR_CREATED_ON, created_on) < 0) {
    log_error("set_attr_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  /* The pledge voucher-request MUST contain a cryptographically strong random
   * or pseudo-random number nonce (see [RFC4086], Section 6.2). As the nonce is
   * usually generated very early in the boot sequence, there is a concern that
   * the same nonce might be generated across multiple boots, or after a factory
   * reset. Different nonces MUST be generated for each bootstrapping attempt,
   * whether in series or concurrently. The freshness of this nonce mitigates
   * against the lack of a real-time clock as explained in Section 2.6.1. */
  if (nonce != NULL) {
    if (set_attr_voucher(voucher, ATTR_NONCE, nonce) < 0) {
      log_error("set_attr_voucher fail");
      free_voucher(voucher);
      return NULL;
    }
  }

  /* The pledge indicates support for the mechanism described in this document,
   * by putting the value "proximity" in the voucher-request, and MUST include
   * the proximity-registrar-cert field (below). */
  if (set_attr_voucher(voucher, ATTR_ASSERTION, VOUCHER_ASSERTION_PROXIMITY) <
      0) {
    log_error("set_attr_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  /* In a pledge voucher-request, this is the first certificate in the TLS
   * server "certificate_list" sequence (see [RFC8446], Section 4.4.2) presented
   * by the registrar to the pledge. That is, it is the end-entity certificate.
   * This MUST be populated in a pledge voucher-request.*/
  if (set_attr_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT,
                       proximity_registrar_cert) < 0) {
    log_error("set_attr_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  /* The serial number of the pledge is included in the voucher-request from the
   * pledge. This value is included as a sanity check only, but it is not to be
   * forwarded by the registrar as described in Section 5.5. */
  if (set_attr_voucher(voucher, ATTR_SERIAL_NUMBER, serial_number) < 0) {
    log_error("set_attr_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  char *cms = sign_cms_voucher(voucher, sign_cert, sign_key, pledge_certs);
  if (cms == NULL) {
    log_error("sign_cms_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  free_voucher(voucher);
  return cms;
}

__must_free char *
sign_voucher_request(const char *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct VoucherBinaryArray *idevid_issuer,
                     const struct VoucherBinaryArray *registrar_cert,
                     const struct VoucherBinaryArray *sign_cert,
                     const struct VoucherBinaryArray *sign_key,
                     const struct buffer_list *pledge_verify_certs,
                     const struct buffer_list *pledge_verify_store,
                     const struct buffer_list *registrar_certs) {

  if (serial_number == NULL) {
    log_error("serial_number param in NULL");
    return NULL;
  }

  if (idevid_issuer == NULL) {
    log_error("idevid_issuer param is NULL");
    return NULL;
  }

  struct Voucher *pledge_voucher_request =
      verify_cms_voucher(pledge_voucher_request_cms, pledge_verify_certs,
                         pledge_verify_store, NULL);
  if (pledge_voucher_request == NULL) {
    log_error("verify_cms_voucher fail");
    return NULL;
  }

  /* check if the serial number in the pledge voucher is the same to idevid
   * cert serial number */
  const char *const *pledge_serial_number =
      get_attr_str_voucher(pledge_voucher_request, ATTR_SERIAL_NUMBER);
  if (pledge_serial_number == NULL) {
    log_error("get_attr_str_voucher fail");
    free_voucher(pledge_voucher_request);
    return NULL;
  }

  if (strcmp(*pledge_serial_number, serial_number) != 0) {
    log_error("wrong pledge voucher serial-number");
    free_voucher(pledge_voucher_request);
    return NULL;
  }

  /* check if the proximity registrar certificat is the same as the registrar
   * certificate */
  const struct VoucherBinaryArray *proximity_registrar_cert =
      get_attr_array_voucher(pledge_voucher_request,
                             ATTR_PROXIMITY_REGISTRAR_CERT);

  if (compare_binary_array(proximity_registrar_cert, registrar_cert) < 1) {
    log_error("proximity cert != registrar cert");
    free_voucher(pledge_voucher_request);
    return NULL;
  }

  /* check if the pledge voucher assertion is proximity */
  const int *pledge_assertion =
      get_attr_enum_voucher(pledge_voucher_request, ATTR_ASSERTION);
  if ((enum VoucherAssertions) * pledge_assertion !=
      VOUCHER_ASSERTION_PROXIMITY) {
    log_error("wrong pledge voucher assertion");
    free_voucher(pledge_voucher_request);
    return NULL;
  }

  struct Voucher *voucher_request = init_voucher();
  if (voucher_request == NULL) {
    log_error("init_voucher fail");
    goto sign_voucher_request_fail;
  }

  /* The registrar SHOULD populate this field with the current date and time
   * when the voucher-request is formed. This field provides additional
   * information to the MASA. */
  if (set_attr_voucher(voucher_request, ATTR_CREATED_ON, created_on) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_voucher_request_fail;
  }

  /* This value, if present, is copied from the pledge voucher-request. The
   * registrar voucher-request MAY omit the nonce as per Section 3.1. */
  if (is_attr_voucher_nonempty(pledge_voucher_request, ATTR_NONCE)) {
    const struct VoucherBinaryArray *nonce =
        get_attr_array_voucher(pledge_voucher_request, ATTR_NONCE);
    if (nonce == NULL) {
      log_error("get_attr_array_voucher fail");
      goto sign_voucher_request_fail;
    }

    if (set_attr_voucher(voucher_request, ATTR_NONCE, nonce) < 0) {
      log_error("set_attr_voucher fail");
      goto sign_voucher_request_fail;
    }
  }

  /* The serial number of the pledge the registrar would like a voucher for. The
   * registrar determines this value by parsing the authenticated pledge IDevID
   * certificate; see Section 2.3. The registrar MUST verify that the
   * serial-number field it parsed matches the serial-number field the pledge
   * provided in its voucher-request. This provides a sanity check useful for
   * detecting error conditions and logging. The registrar MUST NOT simply copy
   * the serial-number field from a pledge voucher-request as that field is
   * claimed but not certified. */
  if (set_attr_voucher(voucher_request, ATTR_SERIAL_NUMBER, serial_number) <
      0) {
    log_error("set_attr_voucher fail");
    goto sign_voucher_request_fail;
  }

  /* The Issuer value from the pledge IDevID certificate is included to ensure
   * unique interpretation of the serial-number. In the case of a nonceless
   * (offline) voucher-request, an appropriate value needs to be configured from
   * the same out-of-band source as the serial-number. */
  if (set_attr_voucher(voucher_request, ATTR_IDEVID_ISSUER, idevid_issuer) <
      0) {
    log_error("set_attr_voucher fail");
    goto sign_voucher_request_fail;
  }

  struct VoucherBinaryArray prior_signed_voucher_request;
  ssize_t length = serialize_base64str2array(
      (const uint8_t *)pledge_voucher_request_cms,
      strlen(pledge_voucher_request_cms), &prior_signed_voucher_request.array);
  if (length < 0) {
    log_error("serialize_base64str2array fail");
    goto sign_voucher_request_fail;
  }
  prior_signed_voucher_request.length = length;

  /* The signed pledge voucher-request SHOULD be included in the registrar
   * voucher-request. The entire CMS-signed structure is to be included and
   * base64 encoded for transport in the JSON structure. */
  if (set_attr_voucher(voucher_request, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                       &prior_signed_voucher_request) < 0) {
    log_error("set_attr_array_voucher fail");
    free_binary_array(&prior_signed_voucher_request);
    goto sign_voucher_request_fail;
  }
  free_binary_array(&prior_signed_voucher_request);

  /* Do not append any certificate list to the voucher request cms structure */
  char *cms =
      sign_cms_voucher(voucher_request, sign_cert, sign_key, registrar_certs);
  if (cms == NULL) {
    log_error("sign_cms_voucher fail");
    goto sign_voucher_request_fail;
  }

  free_voucher(pledge_voucher_request);
  free_voucher(voucher_request);
  return cms;

sign_voucher_request_fail:
  free_voucher(pledge_voucher_request);
  free_voucher(voucher_request);
  return NULL;
}

char *sign_masa_pledge_voucher(const char *voucher_request_cms,
                               const struct tm *expires_on,
                               const struct VoucherBinaryArray *sign_cert,
                               const struct VoucherBinaryArray *sign_key,
                               const struct buffer_list *registrar_verify_certs,
                               const struct buffer_list *registrar_verify_store,
                               const struct buffer_list *pledge_verify_certs,
                               const struct buffer_list *pledge_verify_store,
                               const voucher_req_fn cb) {
  if (expires_on == NULL) {
    log_error("expires_on param in NULL");
    return NULL;
  }

  if (cb == NULL) {
    log_error("cb param in NULL");
    return NULL;
  }

  struct buffer_list *registrar_certs = NULL;
  struct Voucher *voucher_request =
      verify_cms_voucher(voucher_request_cms, registrar_verify_certs,
                         registrar_verify_store, &registrar_certs);
  if (voucher_request == NULL) {
    log_error("verify_cms_voucher fail");
    return NULL;
  }

  /* Extract the serial number from the voucher request yto compare with the
   * pledge's serial number */
  const char *const *voucher_serial_number = NULL;
  if (is_attr_voucher_nonempty(voucher_request, ATTR_SERIAL_NUMBER)) {
    voucher_serial_number =
        get_attr_str_voucher(voucher_request, ATTR_SERIAL_NUMBER);
    if (voucher_serial_number == NULL) {
      log_error("get_attr_str_voucher fail");
      goto sign_masa_pledge_voucher_fail;
    }
  } else {
    log_error("serial-number is missing");
    goto sign_masa_pledge_voucher_fail;
  }

  /* Extract the nonce from the voucher request if present */
  const struct VoucherBinaryArray *nonce = NULL;
  if (is_attr_voucher_nonempty(voucher_request, ATTR_NONCE)) {
    nonce = get_attr_array_voucher(voucher_request, ATTR_NONCE);
    if (nonce == NULL) {
      log_error("get_attr_array_voucher fail");
      goto sign_masa_pledge_voucher_fail;
    }
  }

  /* Check if prior signed voucher request is present in the voucher request */
  const struct VoucherBinaryArray *prior_signed_voucher_request = NULL;
  if (is_attr_voucher_nonempty(voucher_request,
                               ATTR_PRIOR_SIGNED_VOUCHER_REQUEST)) {
    prior_signed_voucher_request = get_attr_array_voucher(
        voucher_request, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST);
    if (prior_signed_voucher_request == NULL) {
      log_error("get_attr_array_voucher fail");
      goto sign_masa_pledge_voucher_fail;
    }
  } else {
    log_error("prior-signed-voucher-request is missing");
    goto sign_masa_pledge_voucher_fail;
  }

  char *pledge_voucher_request_cms = NULL;
  if (serialize_array2base64str(prior_signed_voucher_request->array,
                                prior_signed_voucher_request->length,
                                (uint8_t **)&pledge_voucher_request_cms) < 0) {
    log_error("serialize_array2base64str fail");
    goto sign_masa_pledge_voucher_fail;
  }

  struct Voucher *pledge_voucher_request =
      verify_cms_voucher(pledge_voucher_request_cms, pledge_verify_certs,
                         pledge_verify_store, NULL);
  if (pledge_voucher_request == NULL) {
    log_error("verify_cms_voucher fail");
    sys_free(pledge_voucher_request_cms);
    goto sign_masa_pledge_voucher_fail;
  }
  sys_free(pledge_voucher_request_cms);

  /* Extract the serial number from the pledge voucher and compare with the
   * serial number from the viucher request */
  const char *const *pledge_voucher_serial_number = NULL;
  if (is_attr_voucher_nonempty(pledge_voucher_request, ATTR_SERIAL_NUMBER)) {
    pledge_voucher_serial_number =
        get_attr_str_voucher(pledge_voucher_request, ATTR_SERIAL_NUMBER);
    if (pledge_voucher_serial_number == NULL) {
      log_error("get_attr_str_voucher fail");
      goto sign_masa_pledge_voucher_fail;
    }
  } else {
    log_error("serial-number is missing");
    goto sign_masa_pledge_voucher_fail;
  }

  if (strcmp((const char *)voucher_serial_number,
             (const char *)pledge_voucher_serial_number) != 0) {
    log_error("pledge voucher serial number differs to voucher requests serial "
              "number");
    goto sign_masa_pledge_voucher_fail;
  }

  struct Voucher *masa_pledge_voucher = init_voucher();

  /* The nonce from the pledge if available. */
  if (nonce != NULL) {
    if (set_attr_voucher(masa_pledge_voucher, ATTR_NONCE, nonce) < 0) {
      log_error("set_attr_voucher fail");
      goto sign_masa_pledge_voucher_fail;
    }
  }

  /* The method used to verify the relationship between the pledge and
   * registrar. See Section 5.5.5. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_ASSERTION,
                       VOUCHER_ASSERTION_PROXIMITY) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  struct VoucherBinaryArray *pinned_domain_cert = NULL;
  if (cb((const char *)pledge_voucher_serial_number, registrar_certs,
         &pinned_domain_cert) < 0) {
    log_error("Failure to retrieve pinned domain certificate");
    goto sign_masa_pledge_voucher_fail;
  }

  /* A certificate; see Section 5.5.2. This figure is illustrative; for an
   * example, see Appendix C.2 where an end-entity certificate is used. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_PINNED_DOMAIN_CERT,
                       pinned_domain_cert) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  /* The serial-number as provided in the voucher-request. Also see
   * Section 5.5.5. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_SERIAL_NUMBER,
                       pledge_voucher_serial_number) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  /* Set as appropriate for the pledge's capabilities and as documented in
   * [RFC8366]. The MASA MAY set this field to "false" since setting it to
   * "true" would require that revocation information be available to the
   * pledge, and this document does not make normative requirements for
   * [RFC6961], Section 4.4.2.1 of [RFC8446], or equivalent integrations. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
                       false) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  /* This is set for nonceless vouchers. The MASA ensures the voucher lifetime
   * is consistent with any revocation or pinned-domain-cert consistency checks
   * the pledge might perform. See Section 2.6.1. There are three times to
   * consider: (a) a configured voucher lifetime in the MASA, (b) the expiry
   * time for the registrar's certificate, and (c) any CRL lifetime. The
   * expires-on field SHOULD be before the earliest of these three values.
   * Typically, (b) will be some significant time in the future, but (c) will
   * typically be short (on the order of a week or less). The RECOMMENDED period
   * for (a) is on the order of 20 minutes, so it will typically determine the
   * life span of the resulting voucher. 20 minutes is sufficient time to reach
   * the post-provisional state in the pledge, at which point there is an
   * established trust relationship between the pledge and registrar. The
   * subsequent operations can take as long as required from that point onwards.
   * The lifetime of the voucher has no impact on the life span of the ownership
   * relationship. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_EXPIRES_ON, expires_on) < 0) {
    log_error("set_attr_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  /* Do not append any certificate list to the masa pledge cms structure */
  char *cms = sign_cms_voucher(masa_pledge_voucher, sign_cert, sign_key, NULL);
  if (cms == NULL) {
    log_error("sign_cms_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  free_buffer_list(registrar_certs);
  free_voucher(voucher_request);
  free_voucher(pledge_voucher_request);
  free_voucher(masa_pledge_voucher);

  return cms;
sign_masa_pledge_voucher_fail:
  free_buffer_list(registrar_certs);
  free_voucher(voucher_request);
  free_voucher(pledge_voucher_request);
  free_voucher(masa_pledge_voucher);
  return NULL;
}
