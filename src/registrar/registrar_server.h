/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the registrar server.
 */

#ifndef REGISTRAR_SERVER_H
#define REGISTRAR_SERVER_H

#include "../http/http.h"

struct RegistrarContext {
  void *srv_ctx;
};

/**
 * @brief Starts the registrar server
 *
 * @param[in] confic The https server config
 * @param[out] context The registrar context
 * @return int 0 on success, -1 on failure
 */
int registrar_start(struct http_config *config, struct RegistrarContext **context);

/**
 * @brief Stops the registrar server
 *
 * @param[in] context The registrar context structure
 */
void registrar_stop(struct RegistrarContext *context);
#endif