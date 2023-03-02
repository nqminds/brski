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
 * @param[in] cert The certificate buffer for signing (array in DER format)
 * @param[in] key The private key buffer of the certificate (array in DER
 * format)
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @return char* the signed cms structure in PEM format, NULL on failure
 */
__must_free char *sign_pledge_voucher_request(
    const struct tm *created_on, const struct VoucherBinaryArray *nonce,
    const struct VoucherBinaryArray *proximity_registrar_cert,
    const char *serial_number, const struct VoucherBinaryArray *cert,
    const struct VoucherBinaryArray *key, const struct buffer_list *certs);

/**
 * @brief Signs a voucher request using CMS for a private key (type detected
 * automatically) and output to PEM (base64)
 *
 * Caller is responsible for freeing output PEM string
 *
 * @param[in] pledge_voucher_request The signed pledge voucher request cms
 * structure in PEM (base64) format
 * @param[in] created_on Time when the voucher request is created
 * @param[in] serial_number The serial number string from the idevid certificate
 * @param[in] idevid_issuer The idevid issuer from the idevid certificate
 * @param[in] registrar_cert The registrar certificate (array in DER format)
 * used to create the TLS connection with the pledge
 * @param[in] cert The certificate buffer for signing (array in DER format)
 * @param[in] key The private key buffer of the certificate (array in DER
 * format)
 * @param[in] certs The list of additional certificate buffers (DER format)
 * @return char* the signed cms structure in PEM format, NULL on failure
 */
__must_free char *sign_voucher_request(
    const char *pledge_voucher_request, const struct tm *created_on,
    const char *serial_number, const struct VoucherBinaryArray *idevid_issuer,
    const struct VoucherBinaryArray *registrar_cert,
    const struct VoucherBinaryArray *cert, const struct VoucherBinaryArray *key,
    const struct buffer_list *certs);

#endif
