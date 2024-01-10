/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the pledge utils functions.
 */

#ifndef PLEDGE_UTILS_H
#define PLEDGE_UTILS_H

#include "pledge_config.h"

/**
 * @brief Export a pledge-voucher request to SMIME CMS file
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] tls_cert_path The registrar tls cert binary array
 * @param[in] out_path The path to the export file
 * @return 0 on success, -1 on failure
 */
int voucher_pledge_request_to_smimefile(const struct pledge_config *pconf,
                                        const struct BinaryArray *registrar_tls_cert,
                                        const char *out_path);

/**
 * @brief Export a pledge-voucher request to base64 encoded string
 *
 * The caller is reponsible for freeing the returned string
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] registrar_tls_cert The registrar tls cert binary array
 * @return char * the returned base64 encoded string, NULL on failure
 */
__must_sys_free char *
voucher_pledge_request_to_base64(const struct pledge_config *pconf,
                                 const struct BinaryArray *registrar_tls_cert);
#endif
