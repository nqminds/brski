/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the wolfssl crypto wrapper utilities.
 */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdint.h>

#include "../utils/os.h"
#include "../utils/log.h"

#include "crypto_defs.h"

ssize_t crypto_generate_rsakey(int bits, uint8_t **key) {
  (void)bits;
  (void)key;
  return -1;
}

ssize_t crypto_generate_eckey(uint8_t **key) {
  (void)key;
  return -1;
}

CRYPTO_KEY crypto_eckey2context(uint8_t *key, size_t length) {
  (void)key;
  (void)length;
  return NULL;
}

CRYPTO_KEY crypto_rsakey2context(uint8_t *key, size_t length) {
  (void)key;
  (void)length;
  return NULL;
}

void crypto_free_keycontext(CRYPTO_KEY ctx) {
  (void)ctx;
}