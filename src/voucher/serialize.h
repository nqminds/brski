/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2005, Jouni Malinen <j@w1.fi>, 2023
 * Nquiringminds Ltd SPDX-License-Identifier: MIT
 * @brief File containing the definition of the serialization utilities.
 */
#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "list.h"

/**
 * @brief Encodes an array to base64
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * null terminated to make it easier to use as a C string. The null terminator
 * is not included in out_length.
 *
 * @param[in] src The array to encode
 * @param[in] length The length of the array to encode
 * @param[out] out_length The length of the encoded buffer
 * @return uint8_t * encoded buffer, NULL on failure
 */
uint8_t *serialize_array2base64str(const uint8_t *src, const size_t length,
                                   size_t *out_len);

/**
 * @brief Decodes a base64 encoded array
 *
 * Caller is responsible for freeing the returned buffer.
 *
 * @param[in] src The base64 encoded array
 * @param[in] length The length of the base64 encoded array
 * @param[out] out_length The length of the decoded buffer
 * @return uint8_t * decoded buffer, NULL on failure
 */
uint8_t *serialize_base64str2array(const uint8_t *src, const size_t length,
                                   size_t *out_length);

/**
 * @brief Encodes a bool value to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] value The bool value
 * @return char * encoded bool, NULL on failure
 */
char *serialize_bool2str(const bool value);

/**
 * @brief Encodes a string value to a bool
 *
 *
 * @param[in] str The string value
 * @param[in] length The string length
 * @return int 0=>false, 1=>true, -1 on failure
 */
int serialize_str2bool(const char *str, const size_t length);

/**
 * @brief Encodes a time struct value to a string using
 * ISO 8601 date format %Y-%m-%dT%H:%M:%SZ
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] value The time struct
 * @return char * encoded time, NULL on failure
 */
char *serialize_time2str(const struct tm *value);

/**
 * @brief decodes a ISO 8601 date format %Y-%m-%dT%H:%M:%SZ
 * formated string to a time struct value
 *
 * @param[in] str The iso encoded time string
 * @param[out] tm The output time struct value
 * @return 0 on success, -1 on failure
 */
int serialize_str2time(const char *str, const struct tm *tm);

/**
 * @brief Adds "" to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] value The input string to escape
 * @return char * the escaped string, NULL on failure
 */
char *serialize_escapestr(const char *str);

/**
 * @brief Encodes a key/value list to a json
 * Example:
 * key1:value1,key2:value2 => {key1: value1, key2: value2}
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] kv_list The key/value list
 * @return char * encoded json, NULL on failure
 */
char *serialize_keyvalue2json(const struct keyvalue_list *kv_list);
#endif
