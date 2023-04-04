/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the masa config options.
 */

#ifndef MASA_CONFIG_H
#define MASA_CONFIG_H

#include "../../voucher/array.h"

struct masa_config {
  char *bind_address;
  unsigned int port;
  char *tls_cert_path;
  char *tls_key_path;
  struct BinaryArrayList *cms_add_certs_paths;
};

#endif
