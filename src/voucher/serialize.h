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
uint8_t *serialize_array2base64str(const uint8_t *src, size_t length,
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
uint8_t *serialize_base64str2array(const uint8_t *src, size_t length,
                                   size_t *out_length);

/**
 * @brief Encodes a bool value to a string
 *
 * Caller is responsible for freeing the string
 *
 * @param[in] value The bool value
 * @return char * encoded bool, NULL on failure
 */
char *serialize_bool2str(bool value);
#endif