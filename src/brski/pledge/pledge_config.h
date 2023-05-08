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

#include "../../voucher/array.h"

struct pledge_config {
  char *created_on;
  char *serial_number;
  char *nonce;
  char *idevid_cert_path;
  char *idevid_key_path;
  char *idevid_ca_path;
  char *cms_sign_cert_path;
  char *cms_sign_key_path;
  struct BinaryArrayList *cms_add_certs_paths;
  struct BinaryArrayList *cms_verify_certs_paths;
  struct BinaryArrayList *cms_verify_store_paths;
};

#endif
