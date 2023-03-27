/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the pledge config options.
 */

#ifndef PLEDGE_CONFIG_H
#define PLEDGE_CONFIG_H

struct pledge_config {
  char *created_on;
  char *serial_number;
  char *nonce;
  char *sign_cert_path;
  char *sign_key_path;
  char *additional_certs_path;
};

#endif