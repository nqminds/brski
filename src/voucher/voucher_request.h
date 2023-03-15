/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the voucher request structure.
 */
#ifndef VOUCHER_REQUEST_H
#define VOUCHER_REQUEST_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "../utils/os.h"
#include "voucher.h"

/**
 * @brief Signs a pledge-voucher request using CMS with a private key (type
 * detected automatically) and output to base64 (PEM format)
 *
 * Caller is responsible for freeing the output
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
 * @return char* the signed pledge-voucher CMS structure in base64 (PEM format),
 * NULL on failure
 */
__must_free char *
sign_pledge_voucher_request(const struct tm *created_on,
                            const char *serial_number,
                            const struct VoucherBinaryArray *nonce,
                            const struct VoucherBinaryArray *registrar_tls_cert,
                            const struct VoucherBinaryArray *pledge_sign_cert,
                            const struct VoucherBinaryArray *pledge_sign_key,
                            const struct buffer_list *additional_pledge_certs);

/**
 * @brief Signs a voucher request using CMS with a private key (type detected
 * automatically) and output to base64 (PEM format)
 *
 * Caller is responsible for freeing the output string
 *
 * @param[in] pledge_voucher_request_cms The signed pledge-voucher request CMS
 * structure in base64 (PEM format)
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
 * @return char* the signed CMS structure in base64 (PEM format), NULL on
 * failure
 */
__must_free char *
sign_voucher_request(const char *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct VoucherBinaryArray *idevid_issuer,
                     const struct VoucherBinaryArray *registrar_tls_cert,
                     const struct VoucherBinaryArray *registrar_sign_cert,
                     const struct VoucherBinaryArray *registrar_sign_key,
                     const struct buffer_list *pledge_verify_certs,
                     const struct buffer_list *pledge_verify_store,
                     const struct buffer_list *additional_registrar_certs);

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
    const struct buffer_list *additional_registrar_certs, const void *user_ctx,
    struct VoucherBinaryArray *pinned_domain_cert);

/**
 * @brief Signs a MASA voucher request using CMS with a private key
 * (type detected automatically) and output to base64 (PEM format)
 *
 * Caller is responsible for freeing the output string
 *
 * @param[in] voucher_request_cms The signed pledge voucher request cms
 * structure in base64 (PEM format)
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
 * @return char* the signed CMS structure in base64 (PEM format), NULL on
 * failure
 */
__must_free char *
sign_masa_pledge_voucher(const char *voucher_request_cms,
                         const struct tm *expires_on, const voucher_req_fn cb,
                         const void *user_ctx,
                         const struct VoucherBinaryArray *masa_sign_cert,
                         const struct VoucherBinaryArray *masa_sign_key,
                         const struct buffer_list *registrar_verify_certs,
                         const struct buffer_list *registrar_verify_store,
                         const struct buffer_list *pledge_verify_certs,
                         const struct buffer_list *pledge_verify_store,
                         const struct buffer_list *additional_masa_certs);

/**
 * @brief Verifies a MASA pledge voucher and outputs a pinned domain certificate
 * (DER format)
 *
 * Caller is reponsible for freeing the output certificate list
 *
 * @param[in] masa_pledge_voucher_cms The signed MASA pledge voucher CMS
 * structure in base64 (PEM format)
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
    const char *masa_pledge_voucher_cms, const char *serial_number,
    const struct VoucherBinaryArray *nonce,
    const struct VoucherBinaryArray *registrar_tls_cert,
    const struct buffer_list *domain_store,
    const struct buffer_list *pledge_verify_certs,
    const struct buffer_list *pledge_verify_store,
    struct buffer_list **pledge_out_certs,
    struct VoucherBinaryArray *const pinned_domain_cert);
#endif
