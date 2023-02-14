/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the wolfssl crypto wrapper utilities.
 */
#ifndef CRYPTO_WOLFSSL_H
#define CRYPTO_WOLFSSL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "crypto_defs.h"

/**
 * @brief Generate a private RSA key for a given number of bits
 * The generated key is binary (DER) raw format
 * 
 * Caller is responsible for freeing the key buffer
 * 
 * @param bits[in] Number of key bits for RSA
 * @param key[out] The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_rsakey(int bits, uint8_t **key);

/**
 * @brief Generate a private EC key of the type prime256v1
 * The generated key is binary (DER) raw format
 * 
 * Caller is responsible for freeing the key buffer
 * 
 * @param key[out] The output key buffer
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_eckey(uint8_t **key);

/**
 * @brief Maps a private EC key to a key context
 * 
 * Caller is responsible for freeing the key context
 * 
 * @param key[in] The input key buffer
 * @param length[in] The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_eckey2context(uint8_t *key, size_t length);

/**
 * @brief Maps a private RSA key to a key context
 * 
 * Caller is responsible for freeing the key context
 * 
 * @param key[in] The input key buffer
 * @param length[in] The key buffer length
 * @return CRYPTO_KEY key context, NULL on failure
 */
CRYPTO_KEY crypto_rsakey2context(uint8_t *key, size_t length);

/**
 * @brief Frees a private key context
 * 
 * @param ctx[in] The key context
 */
void crypto_free_keycontext(CRYPTO_KEY ctx);
#endif