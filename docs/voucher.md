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

## Voucher binary array
The voucher library defines a structure to encode binary arrays used in the voucher artifact API calls:
```c
struct VoucherBinaryArray {
  uint8_t *array;
  size_t length;
};
```
If `array == NULL` and `length == 0` the array is considered to be emtpy.

### Voucher binary array API

#### Copies a binary arrays to a destination

```c
int copy_binary_array(struct VoucherBinaryArray *const dst, const struct VoucherBinaryArray *src);
```
Parameters:
* `dst` - The destination binary array and
* `src` - The source binary array.

Return:

`0` on success and `-1` on failure.

#### Compare two binary arrays

```c
int compare_binary_array(const struct VoucherBinaryArray *src, const struct VoucherBinaryArray *dst);
```
Parameters:
* `src` - The source binary array and
* `dst` - The destination binary array.

Return:

`1` if arrays are equal, `0` otherwise and `-1` on failure.

#### Frees a binary array content, i.e., frees the `array` element of the `struct VoucherBinaryArray`.

```c
void free_binary_array(struct VoucherBinaryArray *bin_array);
```
Parameters:
* `array` - The binary array

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
