/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2005, Jouni Malinen <j@w1.fi>, 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the openssl crypto wrapper utilities.
 */
#ifndef CRYPTO_OPENSSL_H
#define CRYPTO_OPENSSL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Generate a private RSA key for a given number of bits
 * The generated key is binary (DER) raw format
 * 
 * Caller is responsible for freeing the key buffer
 * 
 * @param bits[in] Number of key bits for RSA
 * @param key[out] The output key string
 * @return ssize_t the size of the key buffer, -1 on failure
 */
ssize_t crypto_generate_rsakey(int bits, uint8_t **key);

#endif