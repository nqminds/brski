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
int post_brski_requestvoucher(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief BRSKI voucher status handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_voucher_status(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief BRSKI request audit log handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_requestauditlog(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief BRSKI enroll status handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_brski_enrollstatus(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST CA certs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_cacerts(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST simple enroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simpleenroll(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST simple reenroll handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_simplereenroll(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST full cmc handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_fullcmc(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST server keygen handler
 *
 * @return int 0 on success, -1 on failure
 */
int post_est_serverkeygen(ReplyHeader &reply_header, std::string &reply);

/**
 * @brief EST csr attrs handler
 *
 * @return int 0 on success, -1 on failure
 */
int get_est_csrattrs(ReplyHeader &reply_header, std::string &reply);

#endif