/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the https client functions.
 */

#include <string>

extern "C" {
#include "../../utils/log.h"
#include "../../utils/os.h"
}

#ifdef WITH_CPPHTTPLIB_LIB
#include "httplib_wrapper.hpp"
#endif

int https_post_request(const std::string &client_key_path,
                       const std::string &client_cert_path,
                       const std::string &host, int port,
                       const std::string &path, bool verify,
                       const std::string &body, const std::string &content_type,
                       struct HttpResponse &http_res) {
#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_post_request(client_key_path, client_cert_path, host, port,
                              path, verify, body, content_type, http_res);
#else
  log_error("No https client defined");
  return -1;
#endif
}

int https_post_request_ca(const std::string &client_key_path,
                          const std::string &client_cert_path,
                          const std::string &ca, const std::string &host,
                          int port, const std::string &path,
                          const std::string &body,
                          const std::string &content_type,
                          std::string &response) {
#ifdef WITH_CPPHTTPLIB_LIB
  return httplib_post_request_ca(client_key_path, client_cert_path, ca, host,
                                 port, path, body, content_type, response);
#else
  log_error("No https client defined");
  return -1;
#endif
}

std::string get_https_address(const char *bind_address, int port) {
  return "https://" + std::string(bind_address) + ":" + std::to_string(port);
}
