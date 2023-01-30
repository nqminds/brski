/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the registrar server.
 */
#include "../http/http.h"
#include "../http/https_server.h"

#include "registrar_server.h"


int registrar_start(struct http_config *config, struct https_server_context **context) {
  return https_start(config, context);
}

void registrar_stop(struct https_server_context *context) {
  https_stop(context);
}