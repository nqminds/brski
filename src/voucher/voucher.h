/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 Nquiringminds Ltd
 * SPDX-License-Identifier: MIT
 * @brief File containing the definition of the voucher structure.
 */
#ifndef VOUCHER_H
#define VOUCHER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "crypto_defs.h"

struct Voucher;

/**
 * @brief Initialises an empty voucher structure
 *
 * @return struct Voucher* pointer to allocated voucher, NULL on failure
 */
struct Voucher *init_voucher(void);

/**
 * @brief Frees an allocated voucher structure
 *
 * @param[in] voucher The allocated voucher structure
 */
void free_voucher(struct Voucher *voucher);

/**
 * @brief Sets the value for a voucher bool attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The bool voucher attribute
 * @param[in] value The bool attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_bool_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const bool value);

/**
 * @brief Sets the value for a voucher time attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The time voucher attribute
 * @param[in] value The time attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_time_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const struct tm *value);

/**
 * @brief Sets the value for a voucher enum attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The enum voucher attribute
 * @param[in] value The enum attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_enum_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr, const int value);

/**
 * @brief Sets the value for a voucher string attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The string voucher attribute name
 * @param[in] value The string attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_str_voucher(struct Voucher *voucher,
                         const enum VoucherAttributes attr, const char *value);

/**
 * @brief Sets the value for a voucher array attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @param[in] value The array attribute value
 * @return 0 on success, -1 on failure
 */
int set_attr_array_voucher(struct Voucher *voucher,
                           const enum VoucherAttributes attr,
                           const struct VoucherBinaryArray *value);

/**
 * @brief Sets the value for a voucher attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @param[in] __VA_ARGS__ The list of attribute values
 * @return 0 on success, -1 on failure
 */
int set_attr_voucher(struct Voucher *voucher, const enum VoucherAttributes attr,
                     ...);

/**
 * @brief Clears a voucher attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The attribute name
 * @return 0 on success, -1 on failure
 */
int clear_attr_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher bool attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The bool voucher attribute
 * @return const bool* pointer to the bool value, NULL on failure
 */
const bool* get_attr_bool_voucher(const struct Voucher *voucher,
                          const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher time attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The time voucher attribute
 * @return const struct tm * pointer to the time value, NULL on failure
 */
const struct tm * get_attr_time_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher enum attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The enum voucher attribute
 * @return const int* pointer to the enum value, NULL on failure
 */
const int* get_attr_enum_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher string attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The string voucher attribute name
 * @return const char* const* pointer to the string value, NULL on failure
 */
const char* const* get_attr_str_voucher(struct Voucher *voucher,
                         const enum VoucherAttributes attr);

/**
 * @brief Gets the pointer to the value for a voucher array attribute
 *
 * @param[in] voucher The allocated voucher structure
 * @param[in] attr The array voucher attribute name
 * @return const struct VoucherBinaryArray* pointer to the array value, NULL on failure
 */
const struct VoucherBinaryArray* get_attr_array_voucher(struct Voucher *voucher,
                           const enum VoucherAttributes attr);

/**
 * @brief Serializes a voucher to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] voucher The allocated voucher structure
 * @return char* serialized voucher, NULL on failure
 */
char *serialize_voucher(const struct Voucher *voucher);

/**
 * @brief Deserializes a json string to a voucher
 *
 * Caller is responsible for freeing the voucher struct
 *
 * @param[in] json The json string
 * @return struct Voucher * voucher, NULL on failure
 */
struct Voucher *deserialize_voucher(const char *json);

#endif
