/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the https server.
 */
#include "https_server.hpp"
#include "http.hpp"

extern "C" {
#include "../../utils/log.h"
#include "../../utils/os.h"
}

#ifdef WITH_CPPHTTPLIB_LIB
#include "httplib_wrapper.hpp"
#endif

int https_start(struct http_config *config,
                std::vector<struct RouteTuple> &routes, void *user_ctx,
                void **srv_ctx) {
  *srv_ctx = nullptr;

#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_start(config, routes, user_ctx, srv_ctx);
#else
  log_error("No https server defined");
  return -1;
#endif
}

void https_stop(void *srv_ctx) {
#ifdef WITH_CPPHTTPLIB_LIB
  httplib_stop(srv_ctx);
#endif
}
