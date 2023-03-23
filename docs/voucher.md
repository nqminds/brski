# Voucher artifact API

 The voucher artifact is a JSON [RFC8259](https://www.rfc-editor.org/rfc/rfc8259) document that conforms with
 a data model described by YANG [RFC7950](https://www.rfc-editor.org/rfc/rfc7950), is encoded using the rules
 defined in [RFC8259](https://www.rfc-editor.org/rfc/rfc8259), and is signed using (by default) a CMS
 structure [RFC5652](https://www.rfc-editor.org/rfc/rfc5652).

 ```yang
 module: ietf-voucher
    yang-data voucher-artifact:
       +---- voucher
          +---- created-on                       yang:date-and-time
          +---- expires-on?                      yang:date-and-time
          +---- assertion                        enumeration
          +---- serial-number                    string
          +---- idevid-issuer?                   binary
          +---- pinned-domain-cert               binary
          +---- domain-cert-revocation-checks?   boolean
          +---- nonce?                           binary
          +---- last-renewal-date?               yang:date-and-time
          +-- prior-signed-voucher-request?      binary
          +-- proximity-registrar-cert?          binary
 ```

## Voucher attributes

The voucher artifact attributes are define by the enum below:
```c
enum VoucherAttributes {
  ATTR_CREATED_ON = 0,
  ATTR_EXPIRES_ON,
  ATTR_ASSERTION,
  ATTR_SERIAL_NUMBER,
  ATTR_IDEVID_ISSUER,
  ATTR_PINNED_DOMAIN_CERT,
  ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
  ATTR_NONCE,
  ATTR_LAST_RENEWAL_DATE,
  ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,
  ATTR_PROXIMITY_REGISTRAR_CERT
};
```

## Voucher creation/manipulation API

### `init_voucher`
Initialises an empty voucher structure.
```c
__must_free_voucher struct Voucher *init_voucher(void);
```

**Return**:
Pointer to an allocated voucher or NULL on failure.

### `free_voucher`
Frees an allocated voucher structure.
```c
void free_voucher(struct Voucher *voucher);
```
**Parameters**:
* `voucher` - The allocated voucher structure.

### `set_attr_bool_voucher`
Sets the value for a voucher bool attribute.
```c
int set_attr_bool_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const bool value);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The voucher attribute corresponding to the `bool` value and
* `value` - The `bool` attribute value.

**Return**:
`0` on success or `-1` on failure.

### `set_attr_time_voucher`
Sets the value for a voucher time attribute.
```c
int set_attr_time_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const struct tm *value);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The voucher attribute corresponding to the `struct tm` value and
* `value` - The `struct tm` attribute value.

**Return**:
`0` on success or `-1` on failure.

### `set_attr_enum_voucher`
Sets the value for a voucher enum attribute.
```c
int set_attr_enum_voucher(struct Voucher *voucher,
                          const enum VoucherAttributes attr,
                          const int value);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The enum voucher attribute and
* `value` - The enum attribute value.

**Return**:
`0` on success or `-1` on failure.

The enum attribute API sets the value for the assertion attribute with one of the following values as described in [RFC8995](https://www.rfc-editor.org/rfc/rfc8995.html):
```c
enum VoucherAssertions {
  VOUCHER_ASSERTION_NONE = 0,
  VOUCHER_ASSERTION_VERIFIED = 1,
  VOUCHER_ASSERTION_LOGGED = 2,
  VOUCHER_ASSERTION_PROXIMITY = 3
};
```

### `set_attr_str_voucher`
Sets the value for a voucher string attribute.
```c
int set_attr_str_voucher(struct Voucher *voucher,
                         const enum VoucherAttributes attr,
                         const char *value);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The string voucher attribute name and
* `value` - The string attribute value.

**Return**:
`0` on success or `-1` on failure.

### `set_attr_array_voucher`
Sets the value for a voucher array attribute.
```c
int set_attr_array_voucher(struct Voucher *voucher,
                           const enum VoucherAttributes attr,
                           const struct BinaryArray *value);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The array voucher attribute name and
* `value` - The array attribute value.

**Return**:
`0` on success or `-1` on failure.


### `set_attr_voucher`
Sets the value for a voucher attribute.
```c
int set_attr_voucher(struct Voucher *voucher,
                     const enum VoucherAttributes attr,
                     ...);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `attr` - The array voucher attribute name and
* `__VA_ARGS__` - The variable list of attribute values:
    *  `ATTR_CREATED_ON` => `struct tm *`
    *  `ATTR_EXPIRES_ON` => `struct tm *`
    *  `ATTR_LAST_RENEWAL_DATE` => `struct tm *`
    *  `ATTR_ASSERTION` => `enum VoucherAssertions`
    *  `ATTR_SERIAL_NUMBER` => `char *`
    *  `ATTR_IDEVID_ISSUER` => `struct BinaryArray *`
    *  `ATTR_PINNED_DOMAIN_CERT` => `struct BinaryArray *`
    *  `ATTR_NONCE` => `struct BinaryArray *`
    *  `ATTR_PRIOR_SIGNED_VOUCHER_REQUEST` => `struct BinaryArray *`
    *  `ATTR_PROXIMITY_REGISTRAR_CERT` => `struct BinaryArray *`
    *  `ATTR_DOMAIN_CERT_REVOCATION_CHECKS` => `bool`

**Return**:
`0` on success or `-1` on failure.

### `clear_attr_voucher`
Clears a voucher attribute.
```c
int clear_attr_voucher(struct Voucher *voucher,
                       const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The attribute name

**Return**:
`0` on success or `-1` on failure.

### `is_attr_voucher_nonempty`
Checks if a voucher attribute is non empty.
```c
bool is_attr_voucher_nonempty(const struct Voucher *voucher,
                              const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The attribute name.

**Return**:
`true` if non empty or `false` otherwise.

### `get_attr_bool_voucher`
Gets the pointer to the value for a voucher bool attribute.
```c
const bool *get_attr_bool_voucher(const struct Voucher *voucher,
                                  const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The bool voucher attribute.

**Return**:
Pointer to the `bool` value or `NULL` on failure.

### `get_attr_time_voucher`
Gets the pointer to the value for a voucher time attribute.
```c
const struct tm *get_attr_time_voucher(struct Voucher *voucher,
                                       const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The time voucher attribute.

**Return**:
Pointer to the time value or `NULL` on failure.

### `get_attr_enum_voucher`
Gets the pointer to the value for a voucher enum attribute.
```c
const int *get_attr_enum_voucher(struct Voucher *voucher,
                                 const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The enum voucher attribute.

**Return**:
Pointer to the enum value or `NULL` on failure.

### `get_attr_str_voucher`
Gets the pointer to the value for a voucher string attribute.
```c
const char *const *get_attr_str_voucher(struct Voucher *voucher,
                                        const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The string voucher attribute name.

**Return**:
Pointer to the string value or `NULL` on failure.

**Example**:
```c
const char *const *serial_number = get_attr_str_voucher(voucher, ATTR_SERIAL_NUMBER);
if (strcmp(*serial_number, "12345")) {}
```

### `get_attr_array_voucher`
Gets the pointer to the value for a voucher array attribute.
```c
const struct BinaryArray * get_attr_array_voucher(struct Voucher *voucher,
                                                         const enum VoucherAttributes attr);
```
**Parameters**:
* `voucher` - The allocated voucher structure and
* `attr` - The array voucher attribute name.

**Return**:
Pointer to the array value or `NULL` on failure.

## Voucher serialization and deserialization API

### `serialize_voucher`
Serializes a voucher to a string.
```c
__must_free char *serialize_voucher(const struct Voucher *voucher);
```
**Parameters**:
* `voucher` - The allocated voucher structure.

**Return**:
Serialized voucher to string or `NULL` on failure.

**Example**:
```c
struct Voucher *voucher = init_voucher();

set_attr_enum_voucher(voucher, ATTR_ASSERTION, VOUCHER_ASSERTION_PROXIMITY);

char *serialized = serialize_voucher(voucher);

/* ... */

free(serialized);
free_voucher(voucher);
```

### `deserialize_voucher`
Deserializes a json string buffer to a voucher structure.
```c
struct Voucher *deserialize_voucher(const uint8_t *json, const size_t length);
```
**Paramaters**:
* `json` - The json buffer and
* `length` - The json buffer length.

**Return**:
Voucher structure or `NULL` on failure.

**Example**:
```c
struct Voucher *voucher = deserialize_voucher(json, json_length);

/* ... */

free_voucher(voucher);
```

## Voucher CMS signing and verification API

### `sign_eccms_voucher`
Signs a voucher using CMS with an Elliptic Curve private key and output to a binary buffer (`DER` format).
```c
__must_free_binary_array struct BinaryArray *sign_eccms_voucher(struct Voucher *voucher,
                                     const struct BinaryArray *cert,
                                     const struct BinaryArray *key,
                                     const struct BinaryArrayList *certs);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `cert` - The certificate buffer (`DER` format) correspoding to the private key,
* `key` - The Elliptic Curve private key buffer (`DER` format) of the certificate and
* `certs` - The `struct BinaryArrayList` of additional certificate buffers (`DER` format) to be included in the CMS (`NULL` if none).

**Return**:
The signed CMS structure in binary (`DER` format) or `NULL` on failure.

### `sign_rsacms_voucher`
Signs a voucher using CMS with a RSA private key and output to a binary buffer (`DER` format).
```c
__must_free_binary_array struct BinaryArray *sign_rsacms_voucher(struct Voucher *voucher,
                                      const struct BinaryArray *cert,
                                      const struct BinaryArray *key,
                                      const struct BinaryArrayList *certs);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `cert` - The certificate buffer (`DER` format) correspoding to the private key,
* `key` - The RSA private key buffer (`DER` format) of the certificate and
* `certs` - The `struct BinaryArrayList` of additional certificate buffers (`DER` format) to be included in the CMS (`NULL` if none)

**Return**:
The signed CMS structure in binary (`DER` format) or `NULL` on failure.

### `sign_cms_voucher`
Signs a voucher using CMS with a private key (detected automatically) and output as binary array (`DER` format).
```c
__must_free_binary_array struct BinaryArray *sign_cms_voucher(struct Voucher *voucher,
                                   const struct BinaryArray *cert,
                                   const struct BinaryArray *key,
                                   const struct BinaryArrayList *certs);
```
**Parameters**:
* `voucher` - The allocated voucher structure,
* `cert` - The certificate buffer (`DER` format) correspoding to the private key,
* `key` - The private key buffer (`DER` format) of the certificate and
* `certs` - The list of additional certificate buffers (`DER` format) to be included in the CMS (`NULL` if none)

**Return**:
The signed CMS structure as binary array (`DER` format) or `NULL` on failure.

### `verify_cms_voucher`
Verifies a CMS binary buffer and extracts the voucher structure, and the list of included certificates.
```c
__must_free_voucher struct Voucher *verify_cms_voucher(const struct BinaryArray *cms,
                                   const struct BinaryArrayList *certs,
                                   const struct BinaryArrayList *store,
                                   struct BinaryArrayList **out_certs);
```
**Parameters**:
* `cms` - The CMS binary buffer string (`DER` format),
* `certs` - The list of additional certificate buffers (`DER` format),
* `store` - The list of trusted certificate for store (`DER` format). The list's flags is encoded with the  following enum:
    ```c
    enum CRYPTO_CERTIFICATE_TYPE {
      CRYPTO_CERTIFICATE_VALID = 0,
      CRYPTO_CERTIFICATE_CRL,
    };
    ```
    where `CRYPTO_CERTIFICATE_VALID` denotes a standard certificate buffer and `CRYPTO_CERTIFICATE_CRL` denotes a certificate revocation type buffer, and
* `out_certs` - The output list of certificates (`NULL` for empty) from the CMS structure.

**Return**:
The verified voucher structrure or `NULL` on failure.

**Example**:
```c
struct BinaryArrayList *out_certs = NULL;
struct Voucher *voucher = verify_cms_voucher(cms, certs, store, &out_certs);
struct BinaryArrayList *cert = NULL;

dl_list_for_each(el, &out_certs->list, struct BinaryArrayList, list) {
  uint8_t cert_array = cert->buf;
  uint8_t cert_length = cert->length;
  /* ... */
}

/* ... */

free_voucher(voucher);
free_buffer_list(out_certs);
```
