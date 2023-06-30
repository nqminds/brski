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
#include "http.hpp"

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

#endif
