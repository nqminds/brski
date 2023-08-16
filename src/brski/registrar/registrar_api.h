/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the registrar routes.
 */

#ifndef REGISTRAR_ROUTES_H
#define REGISTRAR_ROUTES_H

#include <vector>

#include "../http/http.h"

/**
 * @brief Registrar request voucher handler
 *
 * @return The HTTP status code.
 * @retval 200 OK.
 * @retval 400 Bad Request (malformed request).
 * @retval 500 Internal Server Error (e.g. invalid config).
 * @retval 502 Bad Gateway (e.g. could not send requests to MASA server)
 */
int registrar_requestvoucher(const RequestHeader &request_header,
                             const std::string &request_body,
                             CRYPTO_CERT peer_certificate,
                             ResponseHeader &response_header,
                             std::string &response, void *context);

/**
 * @brief Registrar voucher status handler
 *
 * @return The HTTP status code.
 * @retval 200 OK.
 */
int registrar_voucher_status(const RequestHeader &request_header,
                             const std::string &request_body,
                             CRYPTO_CERT peer_certificate,
                             ResponseHeader &response_header,
                             std::string &response, void *context);

/**
 * @brief Registrar request audit log handler
 *
 * @return The HTTP status code.
 * @retval 200 OK.
 */
int registrar_requestauditlog(const RequestHeader &request_header,
                              const std::string &request_body,
                              CRYPTO_CERT peer_certificate,
                              ResponseHeader &response_header,
                              std::string &response, void *context);

/**
 * @brief Registrar enroll status handler
 *
 * @return The HTTP status code.
 * @retval 200 OK.
 */
int registrar_enrollstatus(const RequestHeader &request_header,
                           const std::string &request_body,
                           CRYPTO_CERT peer_certificate,
                           ResponseHeader &response_header,
                           std::string &response, void *context);

#endif
