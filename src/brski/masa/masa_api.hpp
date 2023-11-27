/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the masa routes.
 */

#ifndef MASA_ROUTES_H
#define MASA_ROUTES_H

#include <vector>

#include "../http/http.hpp"

#define BRSKI_PREFIX_PATH "/.well-known/brski"
#define PATH_BRSKI_REQUESTVOUCHER BRSKI_PREFIX_PATH "/requestvoucher"
#define PATH_BRSKI_VOUCHER_STATUS BRSKI_PREFIX_PATH "/voucher_status"
#define PATH_BRSKI_REQUESTAUDITLOG BRSKI_PREFIX_PATH "/requestauditlog"
#define PATH_BRSKI_ENROLLSTATUS BRSKI_PREFIX_PATH "/enrollstatus"

#define EST_PREFIX_PATH "/.well-known/est"
#define PATH_EST_CACERTS EST_PREFIX_PATH "/cacerts"
#define PATH_EST_SIMPLEENROLL EST_PREFIX_PATH "/simpleenroll"
#define PATH_EST_SIMPLEREENROLL EST_PREFIX_PATH "/simplereenroll"
#define PATH_EST_FULLCMC EST_PREFIX_PATH "/fullcmc"
#define PATH_EST_SERVERKEYGEN EST_PREFIX_PATH "/serverkeygen"
#define PATH_EST_CSRATTRS EST_PREFIX_PATH "/csrattrs"

/**
 * @brief MASA request voucher handler
 *
 * @return int 0 on success, -1 on failure
 */
int masa_requestvoucher(const RequestHeader &request_header,
                        const std::string &request_body,
                        CRYPTO_CERT peer_certificate,
                        ResponseHeader &response_header, std::string &response,
                        void *context);

/**
 * @brief MASA voucher status handler
 *
 * @return int 0 on success, -1 on failure
 */
int masa_voucher_status(const RequestHeader &request_header,
                        const std::string &request_body,
                        CRYPTO_CERT peer_certificate,
                        ResponseHeader &response_header, std::string &response,
                        void *context);

/**
 * @brief MASA request audit log handler
 *
 * @return int 0 on success, -1 on failure
 */
int masa_requestauditlog(const RequestHeader &request_header,
                         const std::string &request_body,
                         CRYPTO_CERT peer_certificate,
                         ResponseHeader &response_header, std::string &response,
                         void *context);

/**
 * @brief MASA enroll status handler
 *
 * @return int 0 on success, -1 on failure
 */
int masa_enrollstatus(const RequestHeader &request_header,
                      const std::string &request_body,
                      CRYPTO_CERT peer_certificate,
                      ResponseHeader &response_header, std::string &response,
                      void *context);

/**
 * @brief EST CA certs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_cacerts(const RequestHeader &request_header,
                    const std::string &request_body,
                    CRYPTO_CERT peer_certificate,
                    ResponseHeader &response_header, std::string &response,
                    void *context);

/**
 * @brief EST simple enroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simpleenroll(const RequestHeader &request_header,
                          const std::string &request_body,
                          CRYPTO_CERT peer_certificate,
                          ResponseHeader &response_header,
                          std::string &response, void *context);

/**
 * @brief EST simple reenroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simplereenroll(const RequestHeader &request_header,
                            const std::string &request_body,
                            CRYPTO_CERT peer_certificate,
                            ResponseHeader &response_header,
                            std::string &response, void *context);

/**
 * @brief EST full cmc handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_fullcmc(const RequestHeader &request_header,
                     const std::string &request_body,
                     CRYPTO_CERT peer_certificate,
                     ResponseHeader &response_header, std::string &response,
                     void *context);

/**
 * @brief EST server keygen handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_serverkeygen(const RequestHeader &request_header,
                          const std::string &request_body,
                          CRYPTO_CERT peer_certificate,
                          ResponseHeader &response_header,
                          std::string &response, void *context);

/**
 * @brief EST csr attrs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_csrattrs(const RequestHeader &request_header,
                     const std::string &request_body,
                     CRYPTO_CERT peer_certificate,
                     ResponseHeader &response_header, std::string &response,
                     void *context);

#endif
