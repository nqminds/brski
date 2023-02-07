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
#include "serialize.h"
#include "voucher.h"

#define MAX_ATTRIBUTE_SIZE 64
#define MAX_SERIAL_NUMBER_SIZE 128

static bool check_binary_array_nonempty(struct VoucherBinaryArray *value) {
  if (value == NULL) {
    return false;
  }

  if (value->array == NULL || !value->length) {
    return false;
  }

  return true;
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

  if (!check_binary_array_nonempty(value)) {
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

static bool is_attr_voucher_nonempty(struct Voucher *voucher,
                                     enum VoucherAttributes attr) {
  switch (attr) {
    case ATTR_CREATED_ON:
      return (voucher->created_on > 0);
    case ATTR_EXPIRES_ON:
      return (voucher->expires_on > 0);
    case ATTR_LAST_RENEWAL_DATE:
      return (voucher->last_renewal_date > 0);
    case ATTR_ASSERTION:
      return (voucher->assertion != VOUCHER_ASSERTION_NONE);
    case ATTR_SERIAL_NUMBER:
      return (voucher->serial_number != NULL);
    case ATTR_IDEVID_ISSUER:
      return check_binary_array_nonempty(&voucher->idevid_issuer);
    case ATTR_PINNED_DOMAIN_CERT:
      return check_binary_array_nonempty(&voucher->pinned_domain_cert);
    case ATTR_NONCE:
      return check_binary_array_nonempty(&voucher->nonce);
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      return check_binary_array_nonempty(
          &voucher->prior_signed_voucher_request);
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      return check_binary_array_nonempty(&voucher->proximity_registrar_cert);
    case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:
      return true;
    default:
      return false;
  }
}

static char *serialize_attr_voucher(struct Voucher *voucher,
                                    enum VoucherAttributes attr) {
  const char *assertion_names[] = VOUCHER_ASSERTION_NAMES;
  size_t out_len = 0;

  switch (attr) {
    case ATTR_CREATED_ON:
      return serialize_time2str(voucher->created_on);
    case ATTR_EXPIRES_ON:
      return serialize_time2str(voucher->expires_on);
    case ATTR_LAST_RENEWAL_DATE:
      return serialize_time2str(voucher->last_renewal_date);
    case ATTR_ASSERTION:
      return serialize_escapestr(assertion_names[voucher->assertion]);
    case ATTR_SERIAL_NUMBER:
      return serialize_escapestr(voucher->serial_number);
    case ATTR_IDEVID_ISSUER:
      return serialize_escapestr((const char *)serialize_array2base64str(
          voucher->idevid_issuer.array, voucher->idevid_issuer.length,
          &out_len));
    case ATTR_PINNED_DOMAIN_CERT:
      return serialize_escapestr((const char *)serialize_array2base64str(
          voucher->pinned_domain_cert.array, voucher->pinned_domain_cert.length,
          &out_len));
    case ATTR_NONCE:
      return serialize_escapestr((const char *)serialize_array2base64str(
          voucher->nonce.array, voucher->nonce.length, &out_len));
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      return serialize_escapestr((const char *)serialize_array2base64str(
          voucher->prior_signed_voucher_request.array,
          voucher->prior_signed_voucher_request.length, &out_len));
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      return serialize_escapestr((const char *)serialize_array2base64str(
          voucher->proximity_registrar_cert.array,
          voucher->proximity_registrar_cert.length, &out_len));
    case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:
      return serialize_bool2str(voucher->domain_cert_revocation_checks);
    default:
      return NULL;
  }
}

struct keyvalue_list *voucher_to_keyvalue(struct Voucher *voucher) {
  struct keyvalue_list *kv_list = init_keyvalue_list();

  if (kv_list == NULL) {
    log_error("init_keyvalue_list fail");
    return NULL;
  }

  enum VoucherAttributes attr = ATTR_CREATED_ON;
  const char *attr_names[] = VOUCHER_ATTRIBUTE_NAMES;
  while (attr <= ATTR_PROXIMITY_REGISTRAR_CERT) {
    if (is_attr_voucher_nonempty(voucher, attr)) {
      char *key = serialize_escapestr(attr_names[attr]);
      if (key == NULL) {
        log_error("serialize_escapestr fail");
        free_keyvalue_list(kv_list);
        return NULL;
      }

      char *value = serialize_attr_voucher(voucher, attr);
      if (value == NULL) {
        log_error("serialize_attr_voucher fail");
        sys_free(key);
        free_keyvalue_list(kv_list);
        return NULL;
      }

      if (push_keyvalue_list(kv_list, key, value) < 0) {
        log_error("push_keyvalue_list fail");
        sys_free(key);
        sys_free(value);
        free_keyvalue_list(kv_list);
        return NULL;
      }
    }
    attr++;
  }
  return kv_list;
}

char *serialize_child_voucher(struct Voucher *voucher) {
  struct keyvalue_list *kv_list = voucher_to_keyvalue(voucher);

  if (kv_list == NULL) {
    log_error("voucher_to_keyvalue fail");
    return NULL;
  }

  char *json = serialize_keyvalue2json(kv_list);
  if (json == NULL) {
    log_error("serialize_keyvalue2json fail");
    free_keyvalue_list(kv_list);
    return NULL;
  }

  free_keyvalue_list(kv_list);
  return json;
}

char *serialize_voucher(struct Voucher *voucher) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  /* Encode the child part of voucher json*/
  char *json_child = serialize_child_voucher(voucher);
  if (json_child == NULL) {
    log_error("serialize_child_voucher fail");
    return NULL;
  }

  struct keyvalue_list *kv_list = init_keyvalue_list();

  if (kv_list == NULL) {
    log_error("voucher_to_keyvalue fail");
    sys_free(json_child);
    return NULL;
  }

  char *key = serialize_escapestr(VOUCHER_ROOT_NAME);
  if (push_keyvalue_list(kv_list, key, json_child) < 0) {
    log_error("push_keyvalue_list fail");
    sys_free(key);
    sys_free(json_child);
    free_keyvalue_list(kv_list);
    return NULL;
  }

  char *json = serialize_keyvalue2json(kv_list);
  if (json == NULL) {
    log_error("serialize_keyvalue2json fail");
    free_keyvalue_list(kv_list);
    return NULL;
  }

  free_keyvalue_list(kv_list);
  return json;
}
