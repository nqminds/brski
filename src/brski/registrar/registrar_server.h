/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the registrar server.
 */

#ifndef REGISTRAR_SERVER_H
#define REGISTRAR_SERVER_H

#include "../http/http.h"
#include "registrar_config.h"

#define BRSKI_PREFIX_PATH "/.well-known/brski"
#define EST_PREFIX_PATH "/.well-known/est"

#define PATH_BRSKI_REQUESTVOUCHER BRSKI_PREFIX_PATH "/requestvoucher"
#define PATH_BRSKI_VOUCHER_STATUS BRSKI_PREFIX_PATH "/voucher_status"
#define PATH_BRSKI_REQUESTAUDITLOG BRSKI_PREFIX_PATH "/requestauditlog"
#define PATH_BRSKI_ENROLLSTATUS BRSKI_PREFIX_PATH "/enrollstatus"
#define PATH_EST_CACERTS EST_PREFIX_PATH "/cacerts"
#define PATH_EST_SIMPLEENROLL EST_PREFIX_PATH "/simpleenroll"
#define PATH_EST_SIMPLEREENROLL EST_PREFIX_PATH "/simplereenroll"
#define PATH_EST_FULLCMC EST_PREFIX_PATH "/fullcmc"
#define PATH_EST_SERVERKEYGEN EST_PREFIX_PATH "/serverkeygen"
#define PATH_EST_CSRATTRS EST_PREFIX_PATH "/csrattrs"

struct RegistrarContext {
  void *srv_ctx;
};

/**
 * @brief Starts the registrar server
 *
 * @param[in] confic The registrar config
 * @param[out] context The registrar context
 * @return int 0 on success, -1 on failure
 */
int registrar_start(struct registrar_config *rconf,
                    struct RegistrarContext **context);

/**
 * @brief Stops the registrar server
 *
 * @param[in] context The registrar context structure
 */
void registrar_stop(struct RegistrarContext *context);
#endif
