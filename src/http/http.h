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

#define MAX_WEB_PATH_LEN 2048

struct http_config {
  char bindAddress[MAX_WEB_PATH_LEN];
  unsigned int port;
};

struct https_server_context {
  void *server;
};  

#endif