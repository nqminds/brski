/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the structures definition for the http(s) servers and clients.
 */

#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <functional>

extern "C" {
#include "../utils/os.h"
}

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

typedef std::function<int(void)> RouteHandle;

struct RouteTuple {
  std::string path;
  enum HTTP_METHOD method;
  RouteHandle handle;
};

struct https_server_context {
  void *server;
};  

struct http_config {
  char bindAddress[MAX_WEB_PATH_LEN];
  unsigned int port;
};

#endif