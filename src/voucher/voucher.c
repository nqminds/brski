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

#include "voucher_crypto.h"
#include "list.h"
#include "serialize.h"
#include "voucher.h"
#include "voucher_defs.h"

#define MAX_ATTRIBUTE_SIZE 64
#define MAX_SERIAL_NUMBER_SIZE 128
#define MAX_VOUCHER_JSON_TOKENS 32

static bool check_size_str_equal(const char *src, const char *dst,
                                 const size_t dst_length) {
  if (strncmp(src, dst, dst_length) == 0 && strlen(src) == dst_length) {
    return true;
  } else {
    return false;
  }
}

static bool
check_binary_array_nonempty(const struct VoucherBinaryArray *value) {
  if (value == NULL) {
    return false;
  }

  if (value->array == NULL && !value->length) {
    return false;
  }

  return true;
}

int copy_binary_array(struct VoucherBinaryArray *const dst,
                      const struct VoucherBinaryArray *src) {
  if (dst == NULL) {
    log_error("dst param is NULL");
    return -1;
  }

  if (src == NULL) {
    log_error("src param is NULL");
    return -1;
  }
  dst->length = 0;
  if ((dst->array = sys_memdup((uint8_t *)src->array, src->length)) == NULL) {
    log_errno("sys_memdup");
    return -1;
  }
  dst->length = src->length;

  return 0;
}

int compare_binary_array(const struct VoucherBinaryArray *src,
                         const struct VoucherBinaryArray *dst) {
  if (src == NULL) {
    log_error("src param is NULL");
    return -1;
  }

  if (dst == NULL) {
    log_error("dst param is NULL");
    return -1;
  }

  if (dst->length != src->length) {
    return 0;
  }

  if (sys_memcmp(dst->array, src->array, src->length) != 0) {
    return 0;
  };

  return 1;
}

void free_binary_array_content(struct VoucherBinaryArray *arr) {
  if (arr != NULL) {
    if (arr->array != NULL) {
      sys_free(arr->array);
      arr->array = NULL;
    }
    arr->length = 0;
  }
}

void free_binary_array(struct VoucherBinaryArray *arr) {
  if (arr != NULL) {
    free_binary_array_content(arr);
    sys_free(arr);
  }
}

void free_voucher(struct Voucher *voucher) {
  if (voucher != NULL) {
    if (voucher->serial_number != NULL) {
      sys_free(voucher->serial_number);
      voucher->serial_number = NULL;
    }

    free_binary_array_content(&voucher->idevid_issuer);
    free_binary_array_content(&voucher->pinned_domain_cert);
    free_binary_array_content(&voucher->nonce);
    free_binary_array_content(&voucher->prior_signed_voucher_request);
    free_binary_array_content(&voucher->proximity_registrar_cert);

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

int set_attr_bool_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const bool value) {
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

static int set_attr_strbool_voucher(struct Voucher *voucher,
                                    const enum VoucherAttributes attr,
                                    const char *value,
                                    const size_t value_length) {
  int bool_value = serialize_str2bool(value, value_length);
  if (bool_value < 0) {
    log_error("serialize_str2bool fail");
    return -1;
  }

  if (set_attr_bool_voucher(voucher, attr, (bool)bool_value) < 0) {
    log_error("set_attr_voucher fail");
    return -1;
  }

  return 0;
}

int set_attr_time_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const struct tm *value) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  switch (attr) {
    case ATTR_CREATED_ON:
      sys_memcpy(&voucher->created_on, value, sizeof(struct tm));
      break;
    case ATTR_EXPIRES_ON:
      sys_memcpy(&voucher->expires_on, value, sizeof(struct tm));
      break;
    case ATTR_LAST_RENEWAL_DATE:
      sys_memcpy(&voucher->last_renewal_date, value, sizeof(struct tm));
      break;
    default:
      log_error("Wrong attribute name");
      return -1;
  }

  return 0;
}

int set_attr_enum_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const int value) {
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

static int set_attr_strenum_voucher(struct Voucher *voucher,
                                    const enum VoucherAttributes attr,
                                    const char *value, const size_t length) {
  const char *assertion_names[] = VOUCHER_ASSERTION_NAMES;
  enum VoucherAssertions assertion = VOUCHER_ASSERTION_VERIFIED;
  while (assertion <= VOUCHER_ASSERTION_PROXIMITY) {
    if (check_size_str_equal(assertion_names[assertion], value,
                             (size_t)length)) {
      return set_attr_enum_voucher(voucher, attr, (int)assertion);
    }
    assertion++;
  }

  return -1;
}

static int set_attr_nstr_voucher(struct Voucher *voucher,
                                 const enum VoucherAttributes attr,
                                 const char *value, const size_t length) {

  if (attr != ATTR_SERIAL_NUMBER) {
    log_error("Wrong attribute name");
    return -1;
  }

  if (length < MAX_SERIAL_NUMBER_SIZE) {
    if ((voucher->serial_number = sys_strndup(value, length)) == NULL) {
      log_errno("sys_strdup");
      return -1;
    }
  } else {
    log_error("Attribute value exceeds max size");
    return -1;
  }

  return 0;
}

int set_attr_str_voucher(struct Voucher *voucher,
                         const enum VoucherAttributes attr, const char *value) {
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

  return set_attr_nstr_voucher(voucher, attr, value,
                               sys_strnlen_s(value, MAX_SERIAL_NUMBER_SIZE));
}

int set_attr_array_voucher(struct Voucher *voucher,
                           const enum VoucherAttributes attr,
                           const struct VoucherBinaryArray *value) {
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

int set_attr_base64_voucher(struct Voucher *voucher,
                            const enum VoucherAttributes attr,
                            const char *value, const size_t length) {
  struct VoucherBinaryArray binary_array;
  ssize_t out_length = 0;
  if ((out_length = serialize_base64str2array((const uint8_t *)value, length,
                                              &binary_array.array)) < 0) {
    log_error("serialize_base64str2array fail");
    return -1;
  }

  binary_array.length = out_length;
  if (set_attr_array_voucher(voucher, attr, &binary_array) < 0) {
    log_error("set_attr_voucher fail");
    free_binary_array_content(&binary_array);
    return -1;
  }

  return 0;
}

int set_attr_voucher(struct Voucher *voucher, const enum VoucherAttributes attr,
                     ...) {
  (void)voucher;

  va_list args;
  va_start(args, attr);

  int res = 0;
  struct tm *time_value;
  int enum_value;
  char *str_value;
  struct VoucherBinaryArray *array_value;
  bool bool_value;

  switch (attr) {
    case ATTR_CREATED_ON:
    case ATTR_EXPIRES_ON:
    case ATTR_LAST_RENEWAL_DATE:
      time_value = va_arg(args, struct tm *);
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

static bool is_attr_time_nonempty(const struct tm *tm) {
  if (!tm->tm_year && !tm->tm_yday && !tm->tm_mon && !tm->tm_wday &&
      !tm->tm_mday && !tm->tm_hour && !tm->tm_min && !tm->tm_sec) {
    return false;
  }

  return true;
}

bool is_attr_voucher_nonempty(const struct Voucher *voucher,
                              const enum VoucherAttributes attr) {
  switch (attr) {
    case ATTR_CREATED_ON:
      return is_attr_time_nonempty(&voucher->created_on);
    case ATTR_EXPIRES_ON:
      return is_attr_time_nonempty(&voucher->expires_on);
    case ATTR_LAST_RENEWAL_DATE:
      return is_attr_time_nonempty(&voucher->last_renewal_date);
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

int clear_attr_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return -1;
  }

  switch (attr) {
    case ATTR_CREATED_ON:
      sys_memset(&voucher->created_on, 0, sizeof(voucher->created_on));
      break;
    case ATTR_EXPIRES_ON:
      sys_memset(&voucher->expires_on, 0, sizeof(voucher->expires_on));
      break;
    case ATTR_LAST_RENEWAL_DATE:
      sys_memset(&voucher->last_renewal_date, 0,
                 sizeof(voucher->last_renewal_date));
      break;
    case ATTR_ASSERTION:
      voucher->assertion = VOUCHER_ASSERTION_NONE;
      break;
    case ATTR_SERIAL_NUMBER:
      if (voucher->serial_number != NULL) {
        sys_free(voucher->serial_number);
        voucher->serial_number = NULL;
      }
      break;
    case ATTR_IDEVID_ISSUER:
      free_binary_array_content(&voucher->idevid_issuer);
      break;
    case ATTR_PINNED_DOMAIN_CERT:
      free_binary_array_content(&voucher->pinned_domain_cert);
      break;
    case ATTR_NONCE:
      free_binary_array_content(&voucher->nonce);
      break;
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      free_binary_array_content(&voucher->prior_signed_voucher_request);
      break;
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      free_binary_array_content(&voucher->proximity_registrar_cert);
      break;
    case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:
      voucher->domain_cert_revocation_checks = false;
      break;
  }

  return 0;
}

const bool *get_attr_bool_voucher(const struct Voucher *voucher,
                                  const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (attr != ATTR_DOMAIN_CERT_REVOCATION_CHECKS) {
    log_error("Wrong attribute name");
    return NULL;
  }

  return &voucher->domain_cert_revocation_checks;
}

const struct tm *get_attr_time_voucher(struct Voucher *voucher,
                                       const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  switch (attr) {
    case ATTR_CREATED_ON:
      return &voucher->created_on;
      break;
    case ATTR_EXPIRES_ON:
      return &voucher->expires_on;
      break;
    case ATTR_LAST_RENEWAL_DATE:
      return &voucher->last_renewal_date;
    default:
      log_error("Wrong attribute name");
      return NULL;
  }
}

const int *get_attr_enum_voucher(struct Voucher *voucher,
                                 const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (attr != ATTR_ASSERTION) {
    log_error("Wrong attribute name");
    return NULL;
  }

  return (const int *)&voucher->assertion;
}

const char *const *get_attr_str_voucher(struct Voucher *voucher,
                                        const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (attr != ATTR_SERIAL_NUMBER) {
    log_error("Wrong attribute name");
    return NULL;
  }

  return (const char *const *)&voucher->serial_number;
}

const struct VoucherBinaryArray *
get_attr_array_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  switch (attr) {
    case ATTR_IDEVID_ISSUER:
      return &voucher->idevid_issuer;
    case ATTR_PINNED_DOMAIN_CERT:
      return &voucher->pinned_domain_cert;
    case ATTR_NONCE:
      return &voucher->nonce;
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      return &voucher->prior_signed_voucher_request;
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      return &voucher->proximity_registrar_cert;
    default:
      log_error("Wrong attribute name");
      return NULL;
  }
}
char *escape_serialize_time(const struct tm *time) {
  char *serialized = serialize_time2str(time);
  if (serialized == NULL) {
    log_error("serialize_time2str fail");
    return NULL;
  }

  char *escaped = serialize_escapestr(serialized);
  if (escaped == NULL) {
    log_error("serialize_escapestr fail");
    sys_free(serialized);
    return NULL;
  }
  sys_free(serialized);
  return escaped;
}

char *escape_serialize_array(const struct VoucherBinaryArray *arr) {
  uint8_t *base64_out = NULL;
  if (serialize_array2base64str(arr->array, arr->length, &base64_out) < 0) {
    log_error("serialize_array2base64str fail");
    return NULL;
  }
  char *escaped = serialize_escapestr((const char *)base64_out);
  if (escaped == NULL) {
    log_error("serialize_escapestr fail");
    sys_free(base64_out);
    return NULL;
  }
  sys_free(base64_out);
  return escaped;
}

static char *serialize_attr_voucher(const struct Voucher *voucher,
                                    const enum VoucherAttributes attr) {
  const char *assertion_names[] = VOUCHER_ASSERTION_NAMES;

  switch (attr) {
    case ATTR_CREATED_ON:
      return escape_serialize_time(&voucher->created_on);
    case ATTR_EXPIRES_ON:
      return escape_serialize_time(&voucher->expires_on);
    case ATTR_LAST_RENEWAL_DATE:
      return escape_serialize_time(&voucher->last_renewal_date);
    case ATTR_ASSERTION:
      return serialize_escapestr(assertion_names[voucher->assertion]);
    case ATTR_SERIAL_NUMBER:
      return serialize_escapestr(voucher->serial_number);
    case ATTR_IDEVID_ISSUER:
      return escape_serialize_array(&voucher->idevid_issuer);
    case ATTR_PINNED_DOMAIN_CERT:
      return escape_serialize_array(&voucher->pinned_domain_cert);
    case ATTR_NONCE:
      return escape_serialize_array(&voucher->nonce);
    case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:
      return escape_serialize_array(&voucher->prior_signed_voucher_request);
    case ATTR_PROXIMITY_REGISTRAR_CERT:
      return escape_serialize_array(&voucher->proximity_registrar_cert);
    case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:
      return serialize_bool2str(voucher->domain_cert_revocation_checks);
    default:
      return NULL;
  }
}

static struct keyvalue_list *
voucher_to_keyvalue(const struct Voucher *voucher) {
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

static char *serialize_child_voucher(const struct Voucher *voucher) {
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

char *serialize_voucher(const struct Voucher *voucher) {
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

static int set_attr_strtime_voucher(struct Voucher *voucher,
                                    const enum VoucherAttributes attr,
                                    const char *value,
                                    const size_t value_length) {
  char buf[64];
  snprintf(buf, 64, "%.*s", (int)value_length, value);

  struct tm tm;
  if (serialize_str2time(buf, &tm) < 0) {
    log_error("serialize_str2time fail");
    return -1;
  }

  if (set_attr_time_voucher(voucher, attr, &tm) < 0) {
    log_error("set_attr_time_voucher fail");
    return -1;
  }

  return 0;
}

static int set_keyvalue_voucher(struct Voucher *voucher, const char *key,
                                const size_t key_length, const char *value,
                                const size_t value_length) {
  const char *attr_names[] = VOUCHER_ATTRIBUTE_NAMES;
  if (check_size_str_equal(attr_names[ATTR_CREATED_ON], key, key_length)) {
    if (set_attr_strtime_voucher(voucher, ATTR_CREATED_ON, value,
                                 value_length) < 0) {
      log_error("set_attr_strtime_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_EXPIRES_ON], key,
                                  key_length)) {
    if (set_attr_strtime_voucher(voucher, ATTR_EXPIRES_ON, value,
                                 value_length) < 0) {
      log_error("set_attr_strtime_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_ASSERTION], key,
                                  key_length)) {
    if (set_attr_strenum_voucher(voucher, ATTR_ASSERTION, value, value_length) <
        0) {
      log_error("set_attr_strenum_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_SERIAL_NUMBER], key,
                                  key_length)) {
    if (set_attr_nstr_voucher(voucher, ATTR_SERIAL_NUMBER, value,
                              value_length) < 0) {
      log_error("set_attr_nstr_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_IDEVID_ISSUER], key,
                                  key_length)) {
    if (set_attr_base64_voucher(voucher, ATTR_IDEVID_ISSUER, value,
                                value_length) < 0) {
      log_error("set_attr_base64_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_PINNED_DOMAIN_CERT], key,
                                  key_length)) {
    if (set_attr_base64_voucher(voucher, ATTR_PINNED_DOMAIN_CERT, value,
                                value_length) < 0) {
      log_error("set_attr_base64_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(
                 attr_names[ATTR_DOMAIN_CERT_REVOCATION_CHECKS], key,
                 key_length)) {
    if (set_attr_strbool_voucher(voucher, ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
                                 value, value_length) < 0) {
      log_error("set_attr_strbool_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_NONCE], key, key_length)) {
    if (set_attr_base64_voucher(voucher, ATTR_NONCE, value, value_length) < 0) {
      log_error("set_attr_base64_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_LAST_RENEWAL_DATE], key,
                                  key_length)) {
    if (set_attr_strtime_voucher(voucher, ATTR_LAST_RENEWAL_DATE, value,
                                 value_length) < 0) {
      log_error("set_attr_strtime_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_PRIOR_SIGNED_VOUCHER_REQUEST],
                                  key, key_length)) {
    if (set_attr_base64_voucher(voucher, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
                                value, value_length) < 0) {
      log_error("set_attr_base64_voucher fail");
      return -1;
    }
  } else if (check_size_str_equal(attr_names[ATTR_PROXIMITY_REGISTRAR_CERT],
                                  key, key_length)) {
    if (set_attr_base64_voucher(voucher, ATTR_PROXIMITY_REGISTRAR_CERT, value,
                                value_length) < 0) {
      log_error("set_attr_base64_voucher fail");
      return -1;
    }
  } else {
    log_error("Unknown voucher json key");
    return -1;
  }

  return 0;
}

struct Voucher *deserialize_voucher(const uint8_t *json, const size_t length) {
  if (json == NULL) {
    log_error("json param is NULL");
    return NULL;
  }

  jsmn_parser parser;
  jsmntok_t tokens[MAX_VOUCHER_JSON_TOKENS];

  jsmn_init(&parser);

  int count = jsmn_parse(&parser, (char *)json, length, tokens,
                         MAX_VOUCHER_JSON_TOKENS);
  if (count < 0) {
    log_error("failed to parse json: %d", count);
    return NULL;
  }

  if (count < 1 || tokens[0].type != JSMN_OBJECT) {
    log_error("json object expected");
    return NULL;
  }

  struct Voucher *voucher = NULL;

  for (int idx = 1; idx < count; idx++) {
    int length = tokens[idx].end - tokens[idx].start;
    /* Find the voucher root key */
    if (strncmp(VOUCHER_ROOT_NAME, (char *)(json + tokens[idx].start),
                length) == 0) {
      voucher = init_voucher();

      idx++;
      if (idx < count && tokens[idx].type == JSMN_OBJECT) {
        /* Iterate over all the key/value pairs of the voucher root */
        for (int j = 0; j < tokens[idx].size; j++) {
          int key_idx = idx + (j * 2) + 1;
          int value_idx = idx + (j * 2 + 1) + 1;
          if (key_idx < count && value_idx < count) {
            jsmntok_t *key_token = &tokens[key_idx];
            jsmntok_t *value_token = &tokens[value_idx];
            size_t key_length = key_token->end - key_token->start;
            size_t value_length = value_token->end - value_token->start;
            const char *key = (char *)(json + key_token->start);
            const char *value = (char *)(json + value_token->start);
            if (set_keyvalue_voucher(voucher, key, key_length, value,
                                     value_length) < 0) {
              log_trace("set_keyvalue_voucher fail");
              goto deserialize_voucher_fail;
            }
          } else {
            log_error("Malformed voucher json");
            goto deserialize_voucher_fail;
          }
        }
      } else {
        log_error("Malformed voucher json");
        goto deserialize_voucher_fail;
      }

      break;
    }
  }

  if (voucher == NULL) {
    log_error("Malformed voucher json");
  }

  return voucher;

deserialize_voucher_fail:
  free_voucher(voucher);
  return NULL;
}

struct VoucherBinaryArray *sign_eccms_voucher(struct Voucher *voucher,
                         const struct VoucherBinaryArray *cert,
                         const struct VoucherBinaryArray *key,
                         const struct buffer_list *certs) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  if (key == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  char *serialized = serialize_voucher(voucher);

  log_trace("%s", serialized);
  if (serialized == NULL) {
    log_error("serialize_voucher fail");
    return NULL;
  }

  uint8_t *cms = NULL;
  ssize_t cms_length =
      crypto_sign_eccms((uint8_t *)serialized, strlen(serialized), cert->array,
                        cert->length, key->array, key->length, certs, &cms);

  if (cms_length < 0) {
    log_error("crypto_sign_eccms fail");
    sys_free(serialized);
    return NULL;
  }
  sys_free(serialized);

  struct VoucherBinaryArray *out = sys_malloc(sizeof(struct VoucherBinaryArray));
  if (out == NULL) {
    log_errno("sys_malloc");
    sys_free(cms);
    return NULL;
  }

  out->array = cms;
  out->length = cms_length;
  return out;
}

struct VoucherBinaryArray *sign_rsacms_voucher(struct Voucher *voucher,
                          const struct VoucherBinaryArray *cert,
                          const struct VoucherBinaryArray *key,
                          const struct buffer_list *certs) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  if (key == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  char *serialized = serialize_voucher(voucher);

  if (serialized == NULL) {
    log_error("serialize_voucher fail");
    return NULL;
  }

  uint8_t *cms = NULL;
  ssize_t cms_length =
      crypto_sign_rsacms((uint8_t *)serialized, strlen(serialized), cert->array,
                         cert->length, key->array, key->length, certs, &cms);

  if (cms_length < 0) {
    log_error("crypto_sign_eccms fail");
    sys_free(serialized);
    return NULL;
  }
  sys_free(serialized);

  struct VoucherBinaryArray *out = sys_malloc(sizeof(struct VoucherBinaryArray));
  if (out == NULL) {
    log_errno("sys_malloc");
    sys_free(cms);
    return NULL;
  }

  out->array = cms;
  out->length = cms_length;
  return out;
}

__must_sys_free struct VoucherBinaryArray *sign_cms_voucher(struct Voucher *voucher,
                                   const struct VoucherBinaryArray *cert,
                                   const struct VoucherBinaryArray *key,
                                   const struct buffer_list *certs) {
  if (voucher == NULL) {
    log_error("voucher param is NULL");
    return NULL;
  }

  if (cert == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  if (key == NULL) {
    log_error("cert param is NULL");
    return NULL;
  }

  char *serialized = serialize_voucher(voucher);

  if (serialized == NULL) {
    log_error("serialize_voucher fail");
    return NULL;
  }

  uint8_t *cms = NULL;
  ssize_t cms_length =
      crypto_sign_cms((uint8_t *)serialized, strlen(serialized), cert->array,
                      cert->length, key->array, key->length, certs, &cms);

  if (cms_length < 0) {
    log_error("crypto_sign_eccms fail");
    sys_free(serialized);
    return NULL;
  }
  sys_free(serialized);

  struct VoucherBinaryArray *out = sys_malloc(sizeof(struct VoucherBinaryArray));
  if (out == NULL) {
    log_errno("sys_malloc");
    sys_free(cms);
    return NULL;
  }

  out->array = cms;
  out->length = cms_length;
  return out;
}

struct Voucher *verify_cms_voucher(const struct VoucherBinaryArray *cms,
                                   const struct buffer_list *certs,
                                   const struct buffer_list *store,
                                   struct buffer_list **out_certs) {
  if (cms == NULL) {
    log_error("cms param is NULL");
    return NULL;
  }

  uint8_t *data = NULL;
  ssize_t data_length =
      crypto_verify_cms(cms->array, cms->length, certs, store, &data, out_certs);

  if (data_length < 0) {
    log_error("crypto_verify_cms fail");
    return NULL;
  }

  struct Voucher *voucher = deserialize_voucher(data, data_length);
  if (voucher == NULL) {
    log_error("deserialize_voucher fail");
    sys_free(data);
    return NULL;
  }

  sys_free(data);

  return voucher;
}
