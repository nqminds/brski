/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the registrar config options.
 */

#ifndef REGISTRAR_CONFIG_H
#define REGISTRAR_CONFIG_H

#include "../http/http.h"

struct registrar_config {
  struct http_config http;
  char *tls_cert_path;
  char *tls_key_path;
};

#endif
