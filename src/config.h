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

/**
 * @brief The App configuration structures. Used for configuring the networking
 * services.
 *
 */
struct app_config {
  bool test;
};

/**
 * @brief Load the app configuration
 *
 * @param filename The app configuration file
 * @param config The configuration structure
 * @return 0 on success, -1 otherwise
 */
int load_app_config(const char *filename, struct app_config *config);

/**
 * @brief Frees the app configuration
 *
 * @param config The app configuration structure
 * @return true on success, false otherwise
 */
void free_app_config(struct app_config *config);

#endif
