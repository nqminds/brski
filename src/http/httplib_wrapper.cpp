/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the http library wrapper.
 */

#include <httplib.h>

extern "C" {
#include "../utils/log.h"
#include "../utils/os.h"
}

#include "http.h"

int httplib_register_routes(httplib::Server *server, std::vector<struct RouteTuple> &routes) {
  for (auto route : routes) {
    log_debug("Registering route=%s", route.path.c_str());
    switch(route.method) {
      case HTTP_METHOD_GET:
        server->Get(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_POST:
        server->Post(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_PUT:
        server->Put(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_DELETE:
        server->Delete(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_OPTIONS:
        server->Options(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_PATCH:
        server->Patch(route.path, [=](const httplib::Request& req, httplib::Response& res) {
          std::string reply;
          ReplyHeader reply_header;
          int status_code = route.handle(reply_header, reply);
          // res.set_content(reply, reply_header);
          res.status = status_code;
        });
        break;
      case HTTP_METHOD_HEAD:
      case HTTP_METHOD_CONNECT:
      case HTTP_METHOD_TRACE:
      case HTTP_METHOD_PRI:
        break;
      default:
        log_error("Uknown HTTP methods");
        return -1;
    }
  }

  return 0;
}

void set_error_handler(httplib::Server *server) {
  server->set_error_handler([](const httplib::Request& req, httplib::Response& res) {
    char buf[BUFSIZ];
    snprintf(buf, sizeof(buf), HTTP_ERROR_REPLY);
    res.set_content(buf, "text/plain");
  });
}

void set_exception_handler(httplib::Server *server) {
  server->set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
    char buf[BUFSIZ];
    try {
      std::rethrow_exception(ep);
    } catch (std::exception &e) {
      snprintf(buf, sizeof(buf), "%s", e.what());
    } catch (...) {
      snprintf(buf, sizeof(buf), "%s", "Unknown Exception");
    }
    res.set_content(buf, "text/plain");
    res.status = 505;
  });
}

int httplib_start(struct http_config *config,
                  std::vector<struct RouteTuple> &routes,
                  struct https_server_context *context) {
  if (context == nullptr) {
    log_error("context param is NULL");
    return -1;
  }

  try {
    const char *cert_path = "";
    const char *private_key_path = "";
    // httplib::SSLServer *server = new httplib::SSLServer(cert_path, private_key_path);
    httplib::Server *server = new httplib::Server();

    if (httplib_register_routes(server, routes) < 0) {
      log_error("httplib_register_routes fail");
      delete server;
      return -1;
    }

    set_error_handler(server);
    set_exception_handler(server);

    context->server = static_cast<void*>(server);
    server->listen(config->bindAddress, config->port);
  } catch (...) {
    log_error("httplib::SSLServer() fail");
    return -1;
  }

  return 0;
}

void httplib_stop(struct https_server_context *context) {
  if (context != nullptr) {
    if (context->server != nullptr) {
      // httplib::SSLServer *server = static_cast<httplib::SSLServer *>(context->server);
      httplib::Server *server = static_cast<httplib::Server *>(context->server);
    }
  }
}
