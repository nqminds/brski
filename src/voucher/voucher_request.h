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
 * @brief Signs a pledge voucher request using CMS for a private key (type
 * detected automatically) and output to PEM (base64)
 *
 * Caller is responsible for freeing output PEM string
 *
 * @param[in] created_on Time when the pledge is created
 * @param[in] nonce Random/pseudo-random nonce
 * @param[in] proximity_registrar_cert The first certificate in the TLS server
 * "certificate_list" sequence presented by the registrar to the pledge (array
 * in DER format)
 * @param[in] serial_number The serial number string of the pledge
 * @param[in] sign_cert The certificate buffer for signing (array in DER format)
 * @param[in] sign_key The private key buffer of the certificate (array in DER
 * format)
 * @param[in] pledge_certs The list of pledge additional certificate buffers
 * (DER format)
 * @return char* the signed cms structure in PEM format, NULL on failure
 */
__must_free char *sign_pledge_voucher_request(
    const struct tm *created_on, const struct VoucherBinaryArray *nonce,
    const struct VoucherBinaryArray *proximity_registrar_cert,
    const char *serial_number, const struct VoucherBinaryArray *sign_cert,
    const struct VoucherBinaryArray *sign_key,
    const struct buffer_list *pledge_certs);

/**
 * @brief Signs a voucher request using CMS for a private key (type detected
 * automatically) and output to PEM (base64)
 *
 * Caller is responsible for freeing output PEM string
 *
 * @param[in] pledge_voucher_request_cms The signed pledge voucher request cms
 * structure in PEM (base64) format
 * @param[in] created_on Time when the voucher request is created
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] idevid_issuer The idevid issuer from the idevid certificate
 * @param[in] registrar_cert The registrar certificate (array in DER format)
 * used to create the TLS connection with the pledge
 * @param[in] sign_cert The certificate buffer for signing (array in DER format)
 * @param[in] sign_key The private key buffer of the certificate (array in DER
 * format)
 * @param[in] pledge_verify_certs The list of additional certificate buffers (DER
 * format) to verify the pledge voucher from the pledge
 * @param[in] pledge_verify_store The list of trusted certificate for store (DER
 * format) to verify the pledge voucher from the pledge
 * @param[in] registrar_certs The list of registrar certificates (DER format)
 * to append to cms
 * @return char* the signed cms structure in PEM format, NULL on failure
 */
__must_free char *
sign_voucher_request(const char *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct VoucherBinaryArray *idevid_issuer,
                     const struct VoucherBinaryArray *registrar_cert,
                     const struct VoucherBinaryArray *sign_cert,
                     const struct VoucherBinaryArray *sign_key,
                     const struct buffer_list *pledge_verify_certs,
                     const struct buffer_list *pledge_verify_store,
                     const struct buffer_list *registrar_certs);

/**
 * @brief Callback function to find a pledge serial number in a
 * DB and a output a pinned domain certificate (array in DER format).
 *
 * Caller is responsible for freeing output pinned domain certificate
 *
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] registrar_certs The list of registrar certificates (DER format)
 * appended to the voucher request cms
 * @param[out] voucher_req_fn The output pinned domain certificate (array in DER format) for the pledge
 * @return 0 on success, -1 on failure
 */
typedef int (*voucher_req_fn)(const char *serial_number,
                               const struct buffer_list *registrar_certs,
                               struct VoucherBinaryArray **pinned_domain_cert);

/**
 * @brief Signs a voucher request for the pledge using CMS for a private key (type detected
 * automatically) and output to PEM (base64)
 *
 * Caller is responsible for freeing output PEM string
 *
 * @param[in] voucher_request_cms The signed pledge voucher request cms
 * structure in PEM (base64) format
 * @param[in] expires_on Time when the new voucher will expire
 * @param[in] sign_cert The certificate buffer for signing (array in DER format)
 * @param[in] sign_key The private key buffer of the certificate (array in DER
 * format)
 * @param[in] registrar_verify_certs The list of additional certificate buffers (DER
 * format) to verify the voucher request from registrar
 * @param[in] registrar_verify_store The list of trusted certificate for store (DER
 * format) to verify the voucher request from registrar
 * @param[in] pledge_verify_certs The list of additional certificate buffers (DER
 * format) to verify the pledge voucher from the pledge
 * @param[in] pledge_verify_store The list of trusted certificate for store (DER
 * format) to verify the pledge voucher from the pledge
 * @param[in] voucher_req_fn The callback function to output pinned domain certificate (array in DER format)
 * @return char* the signed cms structure in PEM format, NULL on failure
 */
__must_free char *sign_masa_pledge_voucher(const char *voucher_request_cms,
                                           const struct tm *expires_on,
                                           const struct VoucherBinaryArray *sign_cert,
                                           const struct VoucherBinaryArray *sign_key,
                                           const struct buffer_list *registrar_verify_certs,
                                           const struct buffer_list *registrar_verify_store,
                                           const struct buffer_list *pledge_verify_certs,
                                           const struct buffer_list *pledge_verify_store,
                                           const voucher_req_fn cb);

__must_free char *verify_masa_pledge_voucher(void);
#endif
