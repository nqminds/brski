/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the https client functions.
 */

#include <cpr/cpr.h>
#include <string>

#include "./https_client.hpp"

extern "C" {
#include "../../utils/log.h"
#include "../../utils/os.h"
}

int https_post_request(const std::string &client_key_path,
                       const std::string &client_cert_path,
                       const std::string &host, int port,
                       const std::string &path, bool verify,
                       const std::string &body, const std::string &content_type,
                       std::string &response) {
  auto key = cpr::ssl::PemKey(std::string{client_key_path});
  auto cert = cpr::ssl::PemCert(std::string{client_cert_path});

  cpr::SslOptions sslOpts = cpr::Ssl(cert, key, cpr::ssl::VerifyHost{verify},
                                     cpr::ssl::VerifyPeer{verify});
  auto url = cpr::Url{get_https_address(host.c_str(), port) + path};
  log_info("Post request to %s", url.c_str());
  cpr::Response res = cpr::Post(
      cpr::Url{get_https_address(host.c_str(), port) + path}, sslOpts,
      cpr::Body{body}, cpr::Header{{"Content-Type", content_type}},
      cpr::DebugCallback([&](cpr::DebugCallback::InfoType type,
                             std::string data, intptr_t userdata) -> void {
        if (type == cpr::DebugCallback::InfoType::TEXT) {
          log_trace("%s", data.c_str());
        }
      }));

  if (res.status_code == 0) {
    log_error("Post request to %s returned error %s", url.c_str(),
              res.error.message.c_str());
    return -1;
  }

  response = res.text;
  return res.status_code;
}

std::string get_https_address(const char *bind_address, int port) {
  return "https://" + std::string(bind_address) + ":" + std::to_string(port);
}
