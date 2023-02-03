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
#define MAX_SERIAL_NUMBER_SIZE 128

static int check_binary_array_nonempty(struct VoucherBinaryArray *value) {
  if (value == NULL) {
    return -1;
  }

  if (value->array == NULL || !value->length) {
    return -1;
  }

  return 0;
}

static int copy_binary_array(struct VoucherBinaryArray *dst,
                             struct VoucherBinaryArray *src) {
  dst->length = src->length;
  if ((dst->array = sys_memdup((uint8_t *)src->array, src->length)) == NULL) {
    log_errno("sys_memdup");
    return -1;
  }

  return 0;
}

static void free_binary_array(struct VoucherBinaryArray *bin_array) {
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

struct Voucher *init_voucher(void) {
  struct Voucher *voucher = sys_zalloc(sizeof(struct Voucher));

  if (voucher == NULL) {
    log_errno("syz_zalloc");
    return NULL;
  }

  return voucher;
}

int set_attr_bool_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                          bool value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (attr != ATTR_DOMAIN_CERT_REVOCATION_CHECKS) {
    log_error("Wrong attribute name");
    return -1;
  }

  voucher->domain_cert_revocation_checks = value;

  return 0;
}

int set_attr_time_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                          time_t value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  switch (attr) {
    case ATTR_CREATED_ON:
      voucher->created_on = value;
      break;
    case ATTR_EXPIRES_ON:
      voucher->expires_on = value;
      break;
    case ATTR_LAST_RENEWAL_DATE:
      voucher->last_renewal_date = value;
      break;
    default:
      log_error("Wrong attribute name");
      return -1;
  }

  return 0;
}

int set_attr_enum_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                          int value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (attr != ATTR_ASSERTION) {
    log_error("Wrong attribute name");
    return -1;
  }

  if (value < (int)VOUCHER_ASSERTION_VERIFIED ||
      value > VOUCHER_ASSERTION_PROXIMITY) {
    log_error("Wrong attribute value");
    return -1;
  }

  voucher->assertion = (enum VoucherAssertions)value;

  return 0;
}

int set_attr_str_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                         char *value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (attr != ATTR_SERIAL_NUMBER) {
    log_error("Wrong attribute name");
    return -1;
  }

  if (value == NULL) {
    log_error("value param is NULL");
    return -1;
  }

  if (sys_strnlen_s(value, MAX_SERIAL_NUMBER_SIZE) < MAX_SERIAL_NUMBER_SIZE) {
    if ((voucher->serial_number = sys_strdup(value)) == NULL) {
      log_errno("sys_strdup");
      return -1;
    }
  } else {
    log_error("Attribute value exceeds max size");
    return -1;
  }

  return 0;
}

int set_attr_array_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                           struct VoucherBinaryArray *value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  if (check_binary_array_nonempty(value) < 0) {
    log_error("value is empty");
    return -1;
  }

  switch (attr) {
    case ATTR_IDEVID_ISSUER:
      if (copy_binary_array(&voucher->idevid_issuer, value) < 0) {
        goto set_attr_array_voucher_fail;
      }
      break;
    case ATTR_PINNED_DOMAIN_CERT:
      if (copy_binary_array(&voucher->pinned_domain_cert, value) < 0) {
        goto set_attr_array_voucher_fail;
      }
      break;
    case ATTR_NONCE:
      if (copy_binary_array(&voucher->nonce, value) < 0) {
        goto set_attr_array_voucher_fail;
      }
      break;
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      if (copy_binary_array(&voucher->prior_signed_voucher_request, value) <
          0) {
        goto set_attr_array_voucher_fail;
      }
      break;
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      if (copy_binary_array(&voucher->proximity_registrar_cert, value) < 0) {
        goto set_attr_array_voucher_fail;
      }
      break;
    default:
      log_error("Wrong attribute name");
      return -1;
  }

  return 0;
set_attr_array_voucher_fail:
  log_error("copy_voucher_array fail");
  return -1;
}

int set_attr_voucher(struct Voucher *voucher, enum VoucherAttributes attr,
                     ...) {
  (void)voucher;

  va_list args;
  va_start(args, attr);

  int res = 0;
  time_t time_value;
  int enum_value;
  char *str_value;
  struct VoucherBinaryArray *array_value;
  bool bool_value;

  switch (attr) {
    case ATTR_CREATED_ON:
    case ATTR_EXPIRES_ON:
    case ATTR_LAST_RENEWAL_DATE:
      time_value = va_arg(args, time_t);
      res = set_attr_time_voucher(voucher, attr, time_value);
      break;
    case ATTR_ASSERTION:
      enum_value = va_arg(args, int);
      res = set_attr_enum_voucher(voucher, attr, enum_value);
      break;
    case ATTR_SERIAL_NUMBER:
      str_value = va_arg(args, char *);
      res = set_attr_str_voucher(voucher, attr, str_value);
      break;
    case ATTR_IDEVID_ISSUER:
    case ATTR_PINNED_DOMAIN_CERT:
    case ATTR_NONCE:
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      array_value = va_arg(args, struct VoucherBinaryArray *);
      res = set_attr_array_voucher(voucher, attr, array_value);
      break;
    case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:
      bool_value = (bool)va_arg(args, int);
      res = set_attr_bool_voucher(voucher, attr, bool_value);
      break;
    default:
      log_error("Wrong attribute name");
      res = -1;
  }
  va_end(args);
  return res;
}
