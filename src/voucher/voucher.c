/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the implementation of the voucher structure.
 */
#include <string.h>

#include <jsmn.h>

#include "../utils/os.h"
#include "voucher.h"

#define MAX_ATTRIBUTE_SIZE 64

struct Voucher *init_voucher(void) {
  struct Voucher *voucher = sys_zalloc(sizeof(struct Voucher));

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

void free_voucher(struct Voucher *voucher) {
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

int check_attr_valid(char *name) {
  if (strncmp(name, CREATED_ON_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, EXPIRES_ON_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, ASSERTION_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, SERIAL_NUMBER_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, IDEVID_ISSUER_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, PINNED_DOMAIN_CERT_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, DOMAIN_CERT_REVOCATION_CHECKS_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, NONCE_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else if (strncmp(name, LAST_RENEWAL_DATE_NAME, MAX_ATTRIBUTE_SIZE) == 0) {
    return 0;
  } else {
    return -1;
  }
}

int set_attr_bool_voucher(struct Voucher *voucher, char *name, bool value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (name == NULL) {
    log_error("name param is NULL");
    return -1;
  }

  if (check_attr_valid(name) < 0) {
    log_error("Unknown attribute");
    return -1;
  }

  if (strcmp(name, DOMAIN_CERT_REVOCATION_CHECKS_NAME) ==
      0) {
    voucher->domain_cert_revocation_checks = value;
  } else {
    log_error("Wrong attribute name");
    return -1;
  }

  return 0;
}

int set_attr_time_voucher(struct Voucher *voucher, char *name, time_t value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (name == NULL) {
    log_error("name param is NULL");
    return -1;
  }

  if (check_attr_valid(name) < 0) {
    log_error("Unknown attribute");
    return -1;
  }

  if (strcmp(name, CREATED_ON_NAME) == 0) {
    voucher->created_on = value;
  } else if (strcmp(name, EXPIRES_ON_NAME) == 0) {
    voucher->expires_on = value;
  } else if (strcmp(name, LAST_RENEWAL_DATE_NAME) == 0) {
    voucher->last_renewal_date = value;
  } else {
    log_error("Wrong attribute name");
    return -1;
  }

  return 0;
}