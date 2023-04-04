/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the app configuration utilities.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include "masa/masa_config.h"
#include "pledge/pledge_config.h"
#include "registrar/registrar_config.h"

/**
 * @brief The BRSKI configuration structures. Used for configuring the
 * server/client/masa
 *
 */
struct brski_config {
  struct pledge_config pconf;
  struct registrar_config rconf;
  struct masa_config mconf;
};

/**
 * @brief Load the BRSKI configuration structure
 *
 * @param[in] filename The BRSKI configuration file
 * @param[in] config The configuration structure
 * @return 0 on success, -1 otherwise
 */
int load_brski_config(const char *filename, struct brski_config *config);

/**
 * @brief Free the BRSKI configuration structure content
 *
 * @param[in] config The configuration structure
 */
void free_config_content(struct brski_config *const config);
#endif
