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

struct registrar_config {
  char *bind_address;
  unsigned int port;
  char *tls_cert_path;
  char *tls_key_path;
  char *tls_ca_path;
  char *cms_sign_cert_path;
  char *cms_sign_key_path;
  struct BinaryArrayList *cms_add_certs_paths;
  struct BinaryArrayList *cms_verify_certs_paths;
  struct BinaryArrayList *cms_verify_store_paths;
};

struct RegistrarContext {
  struct registrar_config *rconf;
  struct masa_config *mconf;
  void *srv_ctx;
};

#endif
