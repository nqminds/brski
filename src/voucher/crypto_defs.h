/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the crypto types.
 */
#ifndef CRYPTO_DEFS_H
#define CRYPTO_DEFS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The generalized context for a private key */
typedef void * CRYPTO_KEY;

/* The generalized context for a certificate */
typedef void * CRYPTO_CERT;

#endif