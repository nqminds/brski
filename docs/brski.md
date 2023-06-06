# BRSKI API
This `BRSKI` API implements the bootstrapping functionalities that allows a pledge to discover or being discovered by an element of the network domain (registrar) that it will belong to and that will perform its bootstrap.

The logical elements of the bootstrapping framework are described in [RFC8995](https://www.rfc-editor.org/rfc/rfc8995.html):
```
                                           +------------------------+
   +--------------Drop-Ship----------------| Vendor Service         |
   |                                       +------------------------+
   |                                       | M anufacturer|         |
   |                                       | A uthorized  |Ownership|
   |                                       | S igning     |Tracker  |
   |                                       | A uthority   |         |
   |                                       +--------------+---------+
   |                                                      ^
   |                                                      |  BRSKI-
   V                                                      |   MASA
+-------+     ............................................|...
|       |     .                                           |  .
|       |     .  +------------+       +-----------+       |  .
|       |     .  |            |       |           |       |  .
|Pledge |     .  |   Join     |       | Domain    <-------+  .
|       |     .  |   Proxy    |       | Registrar |          .
|       <-------->............<-------> (PKI RA)  |          .
|       |        |        BRSKI-EST   |           |          .
|       |     .  |            |       +-----+-----+          .
|IDevID |     .  +------------+             | e.g., RFC 7030 .
|       |     .           +-----------------+----------+     .
|       |     .           | Key Infrastructure         |     .
|       |     .           | (e.g., PKI CA)             |     .
+-------+     .           |                            |     .
              .           +----------------------------+     .
              .                                              .
              ................................................
                            "Domain" Components
```

The API details the functions to allows implementing the below state description for a pledge:

1. Discover a communication channel to a registrar.
2. Identify itself. This is done by presenting an X.509 IDevID credential to the discovered registrar (via the proxy) in a TLS handshake. (The registrar credentials are only provisionally accepted at this time.)
3. Request to join the discovered registrar. A unique nonce is included, ensuring that any responses can be associated with this particular bootstrapping attempt.
4. Imprint on the registrar. This requires verification of the manufacturer-service-provided (MASA) voucher. A voucher contains sufficient information for the pledge to complete authentication of a registrar.
5. Enroll. After imprint, an authenticated TLS (HTTPS) connection exists between the pledge and registrar. EST [RFC7030] can then be used to obtain a domain certificate from a registrar.

## BRSKI Core API

### `sign_pledge_voucher_request`
Signs a pledge voucher request using CMS with a private key (type detected automatically) and output as binary array (`DER` format).
```c
__must_free_binary_array struct BinaryArray * sign_pledge_voucher_request(const struct tm *created_on,
                            const char *serial_number,
                            const struct BinaryArray *nonce,
                            const struct BinaryArray *registrar_tls_cert,
                            const struct BinaryArray *pledge_sign_cert,
                            const struct BinaryArray *pledge_sign_key,
                            const struct BinaryArrayList *additional_pledge_certs);
```
**Parameters**:
* `created_on` - Time when the pledge is created,
* `serial_number` - The serial number string of the pledge,
* `nonce` - Random/pseudo-random nonce (`NULL` for empty),
* `registrar_tls_cert` - The first certificate in the TLS server "certificate_list" sequence presented by the registrar to the pledge (`DER` format),
* `pledge_sign_cert` - The certificate buffer (`DER` format) corresponding to the signig private key,
* `pledge_sign_key` - The private key buffer (`DER` format) for signing the pledge-voucher request and
* `additional_pledge_certs` - The list of additional pledge certificates (`DER` format) to append to CMS (`NULL` for empty).

**Return**:
The signed pledge-voucher CMS structure as bianry array (`DER` format) or `NULL` on failure.

### `sign_voucher_request`
Signs a voucher request using CMS with a private key (type detected automatically) and output as binary array (`DER` format).
```c
__must_free_binary_array struct BinaryArray * sign_voucher_request(const struct BinaryArray *pledge_voucher_request_cms,
                     const struct tm *created_on, const char *serial_number,
                     const struct BinaryArray *idevid_issuer,
                     const struct BinaryArray *registrar_tls_cert,
                     const struct BinaryArray *registrar_sign_cert,
                     const struct BinaryArray *registrar_sign_key,
                     const struct BinaryArrayList *pledge_verify_certs,
                     const struct BinaryArrayList *pledge_verify_store,
                     const struct BinaryArrayList *additional_registrar_certs);
```
**Parameters**:
* `pledge_voucher_request_cms` - The signed pledge-voucher request CMS structure as binary array (`DER` format),
* `created_on` - Time when the voucher request is created,
* `serial_number` - The serial number string from the idevid certificate,
* `idevid_issuer` - The idevid issuer from the idevid certificate,
* `registrar_tls_cert` - The first certificate in the TLS server "certificate_list" sequence presented by the registrar to the pledge (`DER` format),
* `registrar_sign_cert` - The certificate buffer (`DER` format) corresponding to the signing private key,
* `registrar_sign_key` - The private key buffer (`DER` format) for signing the voucher request,
* `pledge_verify_certs` - The list of intermediate certificate buffers (`DER` format) to verify the pledge-voucher request (`NULL` for empty),
* `pledge_verify_store` - The list of trusted certificate buffers (`DER` format) to verify the pledge-voucher request (`NULL` for empty). The lists' flags are described in [verify_cms_voucher](./voucher.md#verify_cms_voucher) function and
* `additional_registrar_certs` - The list of additional registrar certificate buffers (`DER` format) to append to CMS (`NULL` for empty).

**Return**:
The signed CMS structure as binary array (`DER` format) or `NULL` on failure.

### `voucher_req_fn`
Callback function definition to find a pledge serial number in a user defined database and output a pinned domain certificate (DER format).
```c
typedef int (*voucher_req_fn)(
    const char *serial_number,
    const struct BinaryArrayList *additional_registrar_certs, const void *user_ctx,
    struct BinaryArray *pinned_domain_cert);
```

**Parameters**:
* `serial_number` - The serial number string from the idevid certificate,
* `additional_registrar_certs` - The list of additional registrar certificates (`DER` format) appended to the voucher request CMS,
* `user_ctx` - The callback function user context and
* `voucher_req_fn` - The output pinned domain certificate (`DER` format) for the pledge.

**Return**: `0` on success or `-1` on failure.

### `sign_masa_pledge_voucher`
Signs a MASA voucher request using CMS with a private key (type detected automatically) and output as binary array (DER format).

```c
__must_free_binary_array struct BinaryArray *sign_masa_pledge_voucher(const struct BinaryArray *voucher_request_cms,
                         const struct tm *expires_on, const voucher_req_fn cb,
                         void *user_ctx,
                         const struct BinaryArray *masa_sign_cert,
                         const struct BinaryArray *masa_sign_key,
                         const struct BinaryArrayList *registrar_verify_certs,
                         const struct BinaryArrayList *registrar_verify_store,
                         const struct BinaryArrayList *pledge_verify_certs,
                         const struct BinaryArrayList *pledge_verify_store,
                         const struct BinaryArrayList *additional_masa_certs);
```
**Parameters**:
* `voucher_request_cms` - The signed pledge voucher request CMS structure as binary array (`DER` format),
* `expires_on` - Time when the new voucher will expire,
* `voucher_req_fn` - The callback function to output pinned domain certificate (`DER` format),
* `user_ctx` - The callback function user context (`NULL` for empty),
* `masa_sign_cert` - The certificate buffer (`DER` format) corresponding to the signing private key,
* `masa_sign_key` - The private key buffer (`DER` format) for signing the MASA voucher request,
* `registrar_verify_certs` - The list of intermediate certificate buffers (`DER` format) to verify the voucher request from registrar (`NULL` for empty),
* `registrar_verify_store` - The list of trusted certificate buffers (`DER` format) to verify the voucher request from registrar (`NULL` for empty). The lists' flags are described in [verify_cms_voucher](./voucher.md#verify_cms_voucher) function,
* `pledge_verify_certs` - The list of intermediate certificate buffers (`DER` format) to verify the pledge-voucher request (`NULL` for empty),
* `pledge_verify_store` - The list of trusted certificate buffers (`DER` format) to verify the pledge-voucher request (`NULL` for empty). The lists' flags are described in [verify_cms_voucher](./voucher.md#verify_cms_voucher) function and
* `additional_masa_certs` - The list of additional MASA certificate buffers (`DER` format) to append to CMS (`NULL` for empty).

**Return**:
The signed CMS structure as binary array (`DER` format) or `NULL` on failure.

### `verify_masa_pledge_voucher`
Verifies a MASA pledge voucher and outputs a pinned domain certificate (`DER` format) and the CMS appended list of certificates.
```c
int verify_masa_pledge_voucher(
    const struct BinaryArray *masa_pledge_voucher_cms, const char *serial_number,
    const struct BinaryArray *nonce,
    const struct BinaryArray *registrar_tls_cert,
    const struct BinaryArrayList *domain_store,
    const struct BinaryArrayList *pledge_verify_certs,
    const struct BinaryArrayList *pledge_verify_store,
    struct BinaryArrayList **pledge_out_certs,
    struct BinaryArray *const pinned_domain_cert);
```

**Parameters**:
* `masa_pledge_voucher_cms` - The signed MASA pledge voucher CMS structure as binary array (`DER` format),
* `serial_number` - The serial number string from the idevid certificate,
* `nonce` - Random/pseudo-random nonce from the pledge voucher request (`NULL` for empty),
* `registrar_tls_cert` - The first certificate in the TLS server "certificate_list" sequence presented by the registrar to the pledge (`DER` format),
* `domain_store` - The list of trusted certificate buffers (`DER` format) to verify the pinned domain certificate (`NULL` for empty). The lists' flags are described in [verify_cms_voucher](./voucher.md#verify_cms_voucher) function,
* `pledge_verify_certs` - The list of intermediate certificate buffers (`DER` format) to verify the masa pledge voucher (`NULL` for empty),
* `pledge_verify_store` - The list of trusted certificate buffers (`DER` format) to verify the masa pledge voucher (`NULL` for empty). The lists' flags are described in [verify_cms_voucher](./voucher.md#verify_cms_voucher) function,
* `pledge_out_certs` - The list of output certificate buffers (`NULL` for empty) from the MASA pledge CMS structure and
* `pinned_domain_cert` - The output pinned domain certificate buffer (`DER` format)

**Return**:
`0` on success or `-1` on failure.
