/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the https client functions.
 */

#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include <string>

/**
 * @brief Sends a POST request to an endpoint
 *
 * @param[in] client_key_path The https client key path
 * @param[in] client_cert_path The https client cert path
 * @param[in] host The https server host name
 * @param[in] port The https server port value
 * @param[in] path The endpoint route path string
 * @param[in] verify Enable server certificate verification
 * @param[in] body The request body string
 * @param[in] content_type The content typ string
 * @param[out] response The output response string
 * @return int the status code on success, -1 on failure
 */
int https_post_request(const std::string &client_key_path,
                       const std::string &client_cert_path,
                       const std::string &host, int port,
                       const std::string &path, bool verify,
                       const std::string &body, const std::string &content_type,
                       std::string &response);

/**
 * @brief Returns the full address of a HTTPS server
 *
 * @param[in] bind_address The https server bind address string
 * @param[in] port The https server port
 * @return std::string the https full address
 */
std::string get_https_address(const char *bind_address, int port);
#endif
