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
 * @brief Export a pledge-voucher request as base64 CMS file
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] tls_cert_path The path to the registrar certificate file (base64
 * format)
 * @param[in] out_path The path to the export file
 * @return 0 on success, -1 on failure
 */
int export_voucher_pledge_request(const struct pledge_config *pconf,
                                  const char *tls_cert_path,
                                  const char *out_path);

#endif
