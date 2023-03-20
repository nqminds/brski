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

struct VoucherBinaryArray *
sign_pledge_voucher_request(const struct tm *created_on,
                            const char *serial_number,
                            const struct VoucherBinaryArray *nonce,
                            const struct VoucherBinaryArray *registrar_tls_cert,
                            const struct VoucherBinaryArray *pledge_sign_cert,
                            const struct VoucherBinaryArray *pledge_sign_key,
                            const struct buffer_list *additional_pledge_certs) {
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
                       registrar_tls_cert) < 0) {
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

  struct VoucherBinaryArray *cms = sign_cms_voucher(voucher, pledge_sign_cert, pledge_sign_key,
                               additional_pledge_certs);
  if (cms == NULL) {
    log_error("sign_cms_voucher fail");
    free_voucher(voucher);
    return NULL;
  }

  free_voucher(voucher);
  return cms;
}

struct VoucherBinaryArray *
sign_voucher_request(const struct VoucherBinaryArray *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct VoucherBinaryArray *idevid_issuer,
                     const struct VoucherBinaryArray *registrar_tls_cert,
                     const struct VoucherBinaryArray *registrar_sign_cert,
                     const struct VoucherBinaryArray *registrar_sign_key,
                     const struct buffer_list *pledge_verify_certs,
                     const struct buffer_list *pledge_verify_store,
                     const struct buffer_list *additional_registrar_certs) {

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

  if (compare_binary_array(proximity_registrar_cert, registrar_tls_cert) < 1) {
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

  /* The signed pledge voucher-request SHOULD be included in the registrar
   * voucher-request. The entire CMS-signed structure is to be included and
   * base64 encoded for transport in the JSON structure. */
  if (set_attr_voucher(voucher_request, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                       pledge_voucher_request_cms) < 0) {
    log_error("set_attr_array_voucher fail");
    goto sign_voucher_request_fail;
  }

  struct VoucherBinaryArray *cms = sign_cms_voucher(voucher_request, registrar_sign_cert,
                               registrar_sign_key, additional_registrar_certs);
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

struct VoucherBinaryArray *
sign_masa_pledge_voucher(const struct VoucherBinaryArray *voucher_request_cms,
                         const struct tm *expires_on, const voucher_req_fn cb,
                         const void *user_ctx,
                         const struct VoucherBinaryArray *masa_sign_cert,
                         const struct VoucherBinaryArray *masa_sign_key,
                         const struct buffer_list *registrar_verify_certs,
                         const struct buffer_list *registrar_verify_store,
                         const struct buffer_list *pledge_verify_certs,
                         const struct buffer_list *pledge_verify_store,
                         const struct buffer_list *additional_masa_certs) {
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
  struct Voucher *pledge_voucher_request = NULL;
  struct Voucher *masa_pledge_voucher = NULL;

  /* Extract the serial number from the voucher request to compare with the
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

  pledge_voucher_request =
      verify_cms_voucher(prior_signed_voucher_request, pledge_verify_certs,
                         pledge_verify_store, NULL);
  if (pledge_voucher_request == NULL) {
    log_error("verify_cms_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

  /* Extract the serial number from the pledge voucher and compare with the
   * serial number from the voucher request */
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

  if (strcmp((const char *)*voucher_serial_number,
             (const char *)*pledge_voucher_serial_number) != 0) {
    log_error(
        "pledge voucher serial number differs from voucher requests serial "
        "number");
    goto sign_masa_pledge_voucher_fail;
  }

  if ((masa_pledge_voucher = init_voucher()) == NULL) {
    log_error("init_voucher fail");
    goto sign_masa_pledge_voucher_fail;
  }

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

  /* Allocates a pinned domain certificate for a pledge */
  struct VoucherBinaryArray pinned_domain_cert = {0};
  if (cb((const char *)*pledge_voucher_serial_number, registrar_certs, user_ctx,
         &pinned_domain_cert) < 0) {
    log_error("Failure to allocate pinned domain certificate");
    goto sign_masa_pledge_voucher_fail;
  }

  /* A certificate; see Section 5.5.2. This figure is illustrative; for an
   * example, see Appendix C.2 where an end-entity certificate is used. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_PINNED_DOMAIN_CERT,
                       &pinned_domain_cert) < 0) {
    log_error("set_attr_voucher fail");
    free_binary_array_content(&pinned_domain_cert);
    goto sign_masa_pledge_voucher_fail;
  }
  free_binary_array_content(&pinned_domain_cert);

  /* The serial-number as provided in the voucher-request. Also see
   * Section 5.5.5. */
  if (set_attr_voucher(masa_pledge_voucher, ATTR_SERIAL_NUMBER,
                       *pledge_voucher_serial_number) < 0) {
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

  struct VoucherBinaryArray *cms = sign_cms_voucher(masa_pledge_voucher, masa_sign_cert,
                               masa_sign_key, additional_masa_certs);
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

int verify_masa_pledge_voucher(
    const struct VoucherBinaryArray *masa_pledge_voucher_cms, const char *serial_number,
    const struct VoucherBinaryArray *nonce,
    const struct VoucherBinaryArray *registrar_tls_cert,
    const struct buffer_list *domain_store,
    const struct buffer_list *pledge_verify_certs,
    const struct buffer_list *pledge_verify_store,
    struct buffer_list **pledge_out_certs,
    struct VoucherBinaryArray *const pinned_domain_cert) {

  if (serial_number == NULL) {
    log_error("serial_number param is NULL");
    return -1;
  }

  /* The pledge MUST verify the voucher signature using the
   * manufacturer-installed trust anchor(s) associated with the manufacturer's
   * MASA (this is likely included in the pledge's firmware). Management of the
   * manufacturer-installed trust anchor(s) is out of scope of this document;
   * this protocol does not update this trust anchor(s). */
  struct Voucher *masa_pledge_voucher =
      verify_cms_voucher(masa_pledge_voucher_cms, pledge_verify_certs,
                         pledge_verify_store, pledge_out_certs);
  if (masa_pledge_voucher == NULL) {
    log_error("verify_cms_voucher fail");
    return -1;
  }

  /* The pledge MUST verify that the serial-number field of the signed voucher
   * matches the pledge's own serial-number. */
  const char *const *voucher_serial_number = NULL;
  if (is_attr_voucher_nonempty(masa_pledge_voucher, ATTR_SERIAL_NUMBER)) {
    voucher_serial_number =
        get_attr_str_voucher(masa_pledge_voucher, ATTR_SERIAL_NUMBER);
    if (voucher_serial_number == NULL) {
      log_error("get_attr_str_voucher fail");
      goto verify_masa_pledge_voucher_fail;
    }

    if (strcmp(serial_number, *voucher_serial_number) != 0) {
      log_error("pledge voucher serial number differs from masa pledge voucher "
                "serial number=%s",
                *voucher_serial_number);
      goto verify_masa_pledge_voucher_fail;
    }
  } else {
    log_error("serial-number is missing");
    goto verify_masa_pledge_voucher_fail;
  }

  /* The pledge MUST verify the nonce information in the voucher. If present,
   * the nonce in the voucher must match the nonce the pledge submitted to the
   * registrar; vouchers with no nonce can also be accepted (according to local
   * policy; see Section 7.2). */
  if (nonce != NULL) {
    if (is_attr_voucher_nonempty(masa_pledge_voucher, ATTR_NONCE)) {
      const struct VoucherBinaryArray *masa_nonce =
          get_attr_array_voucher(masa_pledge_voucher, ATTR_NONCE);
      if (masa_nonce == NULL) {
        log_error("get_attr_array_voucher fail");
        goto verify_masa_pledge_voucher_fail;
      }

      if (compare_binary_array(nonce, masa_nonce) < 1) {
        log_error("nonce not equal");
        goto verify_masa_pledge_voucher_fail;
      }
    } else {
      log_error("nonce is missing");
      goto verify_masa_pledge_voucher_fail;
    }
  }

  /* The pledge MUST be prepared to parse and fail gracefully from a voucher
   * response that does not contain a pinned-domain-cert field. Such a thing
   * indicates a failure to enroll in this domain, and the pledge MUST attempt
   * joining with other available Join Proxies. */
  if (is_attr_voucher_nonempty(masa_pledge_voucher, ATTR_PINNED_DOMAIN_CERT)) {
    const struct VoucherBinaryArray *masa_pinned_domain_cert =
        get_attr_array_voucher(masa_pledge_voucher, ATTR_PINNED_DOMAIN_CERT);
    if (masa_pinned_domain_cert == NULL) {
      log_error("get_attr_array_voucher fail");
      goto verify_masa_pledge_voucher_fail;
    }

    /* The pledge then evaluates the TLS server certificate chain that it
     * received when the TLS connection was formed using this trust anchor. It
     * is possible that the public key in the pinned-domain-cert directly
     * matches the public key in the end-entity certificate provided by the TLS
     * server. If a registrar's credentials cannot be verified using the
     * pinned-domain-cert trust anchor from the voucher, then the TLS connection
     * is discarded, and the pledge abandons attempts to bootstrap with this
     * discovered registrar.*/
    struct VoucherBinaryArray cert_copy = {0};
    if (copy_binary_array(&cert_copy, masa_pinned_domain_cert) < 0) {
      log_error("copy_binary_array fail");
      goto verify_masa_pledge_voucher_fail;
    }

    struct buffer_list *intermediate_certs = init_buffer_list();
    if (push_buffer_list(intermediate_certs, cert_copy.array, cert_copy.length,
                         0) < 0) {
      log_error("push_buffer_list fail");
      free_buffer_list(intermediate_certs);
      goto verify_masa_pledge_voucher_fail;
    }

    if (crypto_verify_cert(registrar_tls_cert->array,
                           registrar_tls_cert->length, intermediate_certs,
                           domain_store) < 0) {
      log_error("crypto_verify_cert fail");
      free_buffer_list(intermediate_certs);
      goto verify_masa_pledge_voucher_fail;
    }
    free_buffer_list(intermediate_certs);

    if (copy_binary_array(pinned_domain_cert, masa_pinned_domain_cert) < 0) {
      log_error("copy_binary_array fail");
      goto verify_masa_pledge_voucher_fail;
    }
  } else {
    log_error("pinned domain certificate is missing");
    goto verify_masa_pledge_voucher_fail;
  }

  free_voucher(masa_pledge_voucher);
  return 0;

verify_masa_pledge_voucher_fail:
  free_voucher(masa_pledge_voucher);
  return -1;
}
