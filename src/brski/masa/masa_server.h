/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the masa server.
 */

#ifndef MASA_SERVER_H
#define MASA_SERVER_H

#include "../http/http.h"
#include "masa_config.h"

/**
 * @brief Starts the masa server
 *
 * @param[in] rconf The registrar config
 * @param[in] mconf The masa config
 * @param[in] pconf The pledge config
 * @param[out] context The masa context
 * @return int 0 on success, -1 on failure
 */
int masa_start(struct registrar_config *rconf, struct masa_config *mconf,
                    struct pledge_config *pconf,
                    struct MasaContext **context);

/**
 * @brief Stops the masa server
 *
 * @param[in] context The masa context structure
 */
void masa_stop(struct MasaContext *context);
#endif
