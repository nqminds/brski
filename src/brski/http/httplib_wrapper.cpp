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
#include "../../utils/log.h"
#include "../../utils/os.h"
}

#include "http.h"

void get_request_header(const httplib::Request &req,
                        RequestHeader &request_header) {
  for (auto iter : req.headers) {
    try {
      auto value = request_header.at(iter.first);
      request_header[iter.first] = value + ", " + iter.second;
    } catch (std::out_of_range &e) {
      request_header[iter.first] = iter.second;
    }
  }
}

void set_response_header(httplib::Response &res,
                         ResponseHeader &response_header) {
  for (auto iter : response_header) {
    res.set_header(iter.first, iter.second);
  }
}

void set_response(std::string &response, ResponseHeader &response_header,
                  int status_code, httplib::Response &res) {
  set_response_header(res, response_header);
  std::string content_type = response_header["Content-Type"];
  res.set_content(response, content_type);
  res.status = status_code;
}

int httplib_register_routes(httplib::Server *server,
                            std::vector<struct RouteTuple> &routes,
                            void *user_ctx) {
  for (auto route : routes) {
    log_debug("Registering route=%s", route.path.c_str());
    switch (route.method) {
      case HTTP_METHOD_GET:
        server->Get(route.path, [=](const httplib::Request &req,
                                    httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
        });
        break;
      case HTTP_METHOD_POST:
        server->Post(route.path, [=](const httplib::Request &req,
                                     httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
        });
        break;
      case HTTP_METHOD_PUT:
        server->Put(route.path, [=](const httplib::Request &req,
                                    httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
        });
        break;
      case HTTP_METHOD_DELETE:
        server->Delete(route.path, [=](const httplib::Request &req,
                                       httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
        });
        break;
      case HTTP_METHOD_OPTIONS:
        server->Options(route.path, [=](const httplib::Request &req,
                                        httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
        });
        break;
      case HTTP_METHOD_PATCH:
        server->Patch(route.path, [=](const httplib::Request &req,
                                      httplib::Response &res) {
          RequestHeader request_header;
          std::string response;
          ResponseHeader response_header;

          get_request_header(req, request_header);
          std::string body = req.body;
          int status_code =
              route.handle(request_header, body, response_header, response, user_ctx);
          set_response(response, response_header, status_code, res);
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
  server->set_error_handler(
      [](const httplib::Request &req, httplib::Response &res) {
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), HTTP_ERROR_REPLY);
        res.set_content(buf, "text/plain");
      });
}

void set_exception_handler(httplib::Server *server) {
  server->set_exception_handler([](const httplib::Request &req,
                                   httplib::Response &res,
                                   std::exception_ptr ep) {
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

void httplib_stop(void *srv_ctx) {
  if (srv_ctx != nullptr) {
    httplib::Server *server = static_cast<httplib::Server *>(srv_ctx);
    server->stop();
    delete server;
  }
}

int httplib_start(struct http_config *config,
                  std::vector<struct RouteTuple> &routes, void *user_ctx,
                  void **srv_ctx) {
  *srv_ctx = nullptr;

  try {
    httplib::Server *server;
    
    if (config->tls_cert_path == nullptr || config->tls_key_path == nullptr) {
      log_info("Starting the HTTP server at %s:%d", config->bind_address, config->port);
      server = new httplib::Server();
    } else {
      log_info("Starting the HTTPS server at %s:%d", config->bind_address, config->port);
      server = new httplib::SSLServer(config->tls_cert_path, config->tls_key_path);
    }

    if (httplib_register_routes(server, routes, user_ctx) < 0) {
      log_error("httplib_register_routes fail");
      delete server;
      return -1;
    }

    set_error_handler(server);
    set_exception_handler(server);

    *srv_ctx = static_cast<void *>(server);
    server->listen(config->bind_address, config->port);
  } catch (...) {
    log_error("httplib::SSLServer() fail");
    httplib_stop(srv_ctx);
    return -1;
  }

  return 0;
}

int httplib_post_request(const std::string &address, const std::string &path, bool verify, const std::string &body,
              const std::string &content_type, std::string &response) {
  httplib::Client cli(address);                

  cli.enable_server_certificate_verification(verify);

  if (httplib::Result res = cli.Post(path, body, content_type)) {
    response = res->body;
    return res->status;
  } else {
    std::string err = to_string(res.error());
    log_error("httplib::Client fail with \"%s\"", err.c_str());

    return -1;
  }
}