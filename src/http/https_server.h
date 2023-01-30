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

#include "http.h"

/**
 * @brief Starts the https server
 *
 * @param[out] context The https server context
 * @return int 0 on success, -1 on failure
 */
int https_start(struct https_server_context **context);

/**
 * @brief Stops the https server
 *
 * @param[in] context The supervisor context structure
 */
void https_stop(struct https_server_context *context);
#endif