/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the http library wrapper.
 */

#ifndef HTTPLIB_WRAPPER_H
#define HTTPLIB_WRAPPER_H

#include <vector>
#include "http.h"

/**
 * @brief Starts the http library server
 *
 * @param[in] config The https server config
 * @param[in] routes The https server routes
 * @param[in] user_ctx The user context
 * @param[out] context The https server context
 * @return int 0 on success, -1 on failure
 */
int httplib_start(struct http_config *config,
                  std::vector<struct RouteTuple> &routes, void *user_ctx,
                  void **srv_ctx);

/**
 * @brief Stops the http library server
 *
 * @param[in] context The https server context structure
 */
void httplib_stop(void *srv_ctx);

/**
 * @brief Sends a POST request to an endpoint
 *
 * @param[in] address The https server address
 * @param[in] path The endpoint route path string
 * @param[in] verify Enable server certificate verification
 * @param[in] body The request body string
 * @param[in] content_type The content typ string
 * @param[out] response The output response string
 * @return int the status code on success, -1 on failure
 */
int httplib_post_request(const std::string &address, const std::string &path,
                         bool verify, const std::string &body,
                         const std::string &content_type,
                         std::string &response);
#endif
