/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the https server.
 */

#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H
#include <vector>

#include "http.h"

/**
 * @brief Starts the https server
 *
 * @param[in] confic The https server config
 * @param[in] routes The https server routes
 * @param[out] context The https server context
 * @return int 0 on success, -1 on failure
 */
int https_start(struct http_config *config,
                std::vector<struct RouteTuple> &routes,
                struct https_server_context **context);

/**
 * @brief Stops the https server
 *
 * @param[in] context The supervisor context structure
 */
void https_stop(struct https_server_context *context);
#endif