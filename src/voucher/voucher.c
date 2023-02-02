/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the voucher structure.
 */
#include <jsmn.h>

#include "voucher.h"
#include "../utils/os.h"

struct Voucher* init_voucher(void) {
  struct Voucher* voucher = sys_zalloc(sizeof(struct Voucher));

  if (voucher == NULL) {
    log_errno("syz_zalloc");
    return NULL;
  }

  return voucher;
}

void free_binary_array(struct BinaryArray *bin_array) {
  if (bin_array != NULL) {
    if (bin_array->array != NULL) {
      sys_free(bin_array->array);
    }
    bin_array->length = 0;
  }
}

void free_voucher(struct Voucher* voucher) {
  if (voucher != NULL) {
    if (voucher->serial_number != NULL) {
      sys_free(voucher->serial_number);
    }

    free_binary_array(&voucher->idevid_issuer);
    free_binary_array(&voucher->pinned_domain_cert);
    free_binary_array(&voucher->nonce);
    sys_free(voucher);
  }
}