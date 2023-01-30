/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the registrar routes.
 */

#ifndef REGISTRAR_ROUTES_H
#define REGISTRAR_ROUTES_H

#include <vector>

#include "../http/http.h"

/**
 * @brief Setups the registrar route handlers
 *
 * @param[out] routes The array of route tuples
 * @return int 0 on success, -1 on failure
 */
int setup_registrar_routes(std::vector<struct RouteTuple> &routes);

#endif