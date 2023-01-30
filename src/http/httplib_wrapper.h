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

#include "http.h"

/**
 * @brief Starts the http library server
 *
 * @param[out] context The https server context
 * @return int 0 on success, -1 on failure
 */
int httplib_start(struct https_server_context *context);

/**
 * @brief Stops the http library server
 *
 * @param[in] context The supervisor context structure
 */
void httplib_stop(struct https_server_context *context);
#endif