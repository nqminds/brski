/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the structures definition for the http(s) servers and
 * clients.
 */

#ifndef HTTP_H
#define HTTP_H

#include <functional>
#include <map>
#include <string>

extern "C" {
#include "../../utils/os.h"
#include "../../voucher/crypto.h"
}

#define MAX_WEB_PATH_LEN 2048

#define HTTP_ERROR_REPLY "Router error"

enum HTTP_METHOD {
  HTTP_METHOD_GET = 0,
  HTTP_METHOD_HEAD,
  HTTP_METHOD_POST,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
  HTTP_METHOD_CONNECT,
  HTTP_METHOD_OPTIONS,
  HTTP_METHOD_TRACE,
  HTTP_METHOD_PATCH,
  HTTP_METHOD_PRI
};

typedef std::map<std::string, std::string> RequestHeader;
typedef std::map<std::string, std::string> ResponseHeader;
typedef std::function<int(
    const RequestHeader &request_header, const std::string &request_body,
    CRYPTO_CERT peer_certificate, ResponseHeader &response_header,
    std::string &response, void *user_ctx)>
    RouteHandle;

struct RouteTuple {
  std::string path;
  enum HTTP_METHOD method;
  RouteHandle handle;
};

struct HttpResponse {
  std::string response;
  CRYPTO_CERT peer_certificate;
};

struct http_config {
  char *bind_address;
  unsigned int port;
  char *tls_cert_path;
  char *tls_key_path;
  char *client_ca_cert_path;
  char *client_ca_cert_dir_path;
  char *private_key_password;
};

#endif
