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

#include "http/http.h"

/**
 * @brief The BRSKI configuration structures. Used for configuring the server/client/masa
 *
 */
struct brski_config {
  struct http_config hconf;
};

/**
 * @brief Load the BRSKI configuration structure
 *
 * @param filename The BRSKI configuration file
 * @param config The configuration structure
 * @return 0 on success, -1 otherwise
 */
int load_brski_config(const char *filename, struct brski_config *config);
#endif
