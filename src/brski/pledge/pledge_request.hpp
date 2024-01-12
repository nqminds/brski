/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the pledge request functions.
 */

#ifndef PLEDGE_REQUEST_H
#define PLEDGE_REQUEST_H

#include <string>

#include "../masa/masa_config.h"
#include "../registrar/registrar_config.h"
#include "pledge_config.h"

/**
 * @brief Sends a pledge voucher POST request to the registrar
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] rconf The registrar configuration structure
 * @param[in] mconf The masa configuration structure
 * @param[out] response The pinned domain certificate in DER format, encoded as
 * base64.
 * @return int 0 on success, -1 on failure
 */
int post_voucher_pledge_request(struct pledge_config *pconf,
                                struct registrar_config *rconf,
                                struct masa_config *mconf,
                                std::string &response);

/**
 * @brief Signs a certificate after sending a pledge voucher POST request to the registrar
 *
 * @param[in] pconf The pledge configuration structure
 * @param[in] rconf The registrar configuration structure
 * @param[in] mconf The masa configuration structure
 * @param[in] cert_to_sign_path The path of the certificate to sing
 * @param[out] cert_out The signed certificate in DER format, encoded as
 * base64.
 * @return int 0 on success, -1 on failure
 */
int post_sign_cert(struct pledge_config *pconf,
                   struct registrar_config *rconf,
                   struct masa_config *mconf,
                   const char *cert_to_sign_path,
                   std::string &response);

#endif
