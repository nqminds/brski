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
 * @brief BRSKI request voucher handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_requestvoucher(RequestHeader &request_header,
                              ResponseHeader &response_header,
                              std::string &response,
                              void *context);

/**
 * @brief BRSKI voucher status handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_voucher_status(RequestHeader &request_header,
                              ResponseHeader &response_header,
                              std::string &response,
                              void *context);

/**
 * @brief BRSKI request audit log handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_requestauditlog(RequestHeader &request_header,
                              ResponseHeader &response_header,
                              std::string &response,
                              void *context);

/**
 * @brief BRSKI enroll status handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_enrollstatus(RequestHeader &request_header,
                              ResponseHeader &response_header,
                              std::string &response,
                              void *context);

/**
 * @brief EST CA certs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_cacerts(RequestHeader &request_header,
                    ResponseHeader &response_header,
                    std::string &response,
                    void *context);

/**
 * @brief EST simple enroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simpleenroll(RequestHeader &request_header,
                          ResponseHeader &response_header,
                          std::string &response,
                          void *context);

/**
 * @brief EST simple reenroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simplereenroll(RequestHeader &request_header,
                            ResponseHeader &response_header,
                            std::string &response,
                            void *context);

/**
 * @brief EST full cmc handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_fullcmc(RequestHeader &request_header,
                     ResponseHeader &response_header,
                     std::string &response,
                     void *context);

/**
 * @brief EST server keygen handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_serverkeygen(RequestHeader &request_header,
                          ResponseHeader &response_header,
                          std::string &response,
                          void *context);

/**
 * @brief EST csr attrs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_csrattrs(RequestHeader &request_header,
                     ResponseHeader &response_header,
                     std::string &response,
                     void *context);

#endif