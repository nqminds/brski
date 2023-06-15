# BRSKI Usage

## Voucher Library Usage
## Example CMakeLists.txt file
Below is an example `cmake` config file to import the voucher library into a `cmake` project and use it with OpenSSL. The path for the static voucher library file `libvoucher.a` is set by the
`LIBVOUCHER_LIBRARY` variable and the voucher library include path is set by `LIBVOUCHER_INCLUDE_PATH` variable.

```cmake
cmake_minimum_required(VERSION 3.1...3.26)

project(
  LibTest
  VERSION 1.0
  LANGUAGES C)

find_package(OpenSSL 3 MODULE REQUIRED COMPONENTS Crypto SSL)
message("Found OpenSSL ${OPENSSL_VERSION} crypto library")
add_library(OpenSSL3::Crypto ALIAS OpenSSL::Crypto)
add_library(OpenSSL3::SSL ALIAS OpenSSL::SSL)
set(LIBOPENSSL3_INCLUDE_PATH "${OPENSSL_INCLUDE_DIR}")

set(LIBVOUCHER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/include/voucher")
set(LIBVOUCHER_LIB_PATH "${CMAKE_SOURCE_DIR}/lib")
set(LIBVOUCHER_LIBRARY "${LIBVOUCHER_LIB_PATH}/libvoucher.a")

add_library(Voucher::Voucher STATIC IMPORTED)
set_target_properties(Voucher::Voucher PROPERTIES
  IMPORTED_LOCATION "${LIBVOUCHER_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${LIBVOUCHER_INCLUDE_PATH}"
)

add_executable(libtest libtest.c)
target_link_libraries(libtest PRIVATE Voucher::Voucher OpenSSL::Crypto)
```

## BRSKI Tool usage

The BRSKI `generate_test_certs` test creates a `test-config.ini` file
(located at `${CMAKE_BINARY_DIR}/tests/brski/test-config.ini`),
which has some pregenerated example certificates for running the MASA,
registrar, and pledge on localhost.

### Exporting a pledge voucher request

To export a pledge voucher request to a `CMS` SMIME file `out.cms` use the command `epvr` as following:
```bash
$ brski -c config.ini -o out.cms epvr
```
where the example `config.ini` file is defined as follows:

```ini
[pledge]
createdOn = "1973-11-29T21:33:09Z"
serialNumber = "12345"
nonce = "some-nonce-value-in-base64"
idevidKeyPath = ""
idevidCertPath = ""
idevidCACertPath = ""
cmsSignKeyPath = "/absolute_path_to/pledge-cms.key"
cmsSignCertPath = "/absolute_path_to/pledge-cms.crt"
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[registrar]
bindAddress = ""
port = 0
tlsKeyPath = "/absolute_path_to/registrar-tls.key"
tlsCertPath = "/absolute_path_to/registrar-tls.crt"
tlsCACertPath = ""
cmsSignCertPath = ""
cmsSignKeyPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[masa]
bindAddress = ""
port = 0
expiresOn = ""
ldevidCAKeyPath = ""
ldevidCACertPath = ""
tlsKeyPath = ""
tlsCertPath = ""
tlsCACertPath = ""
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""
```

### Sending a pledge-voucher request to the registrar

To send a pledge-voucher request to a registrar use the command `preq` as following:
```bash
$ brski -c config.ini preq
```
where the example `config.ini` file is defined as follows:

```ini
[pledge]
createdOn = "1973-11-29T21:33:09Z"
serialNumber = "idev-serial12345"
nonce = "some-nonce-value-in-base64"
idevidKeyPath = "/absolute_path_to/idevid.key"
idevidCertPath = "/absolute_path_to/idevid.crt"
idevidCACertPath = "/absolute_path_to/idevid-ca.crt"
cmsSignKeyPath = "/absolute_path_to/pledge-cms.key"
cmsSignCertPath = "/absolute_path_to/pledge-cms.crt"
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[registrar]
bindAddress = "https://registrar-address.com"
port = 12345
tlsKeyPath = ""
tlsCertPath = "/absolute_path_to/registrar-tls.crt"
tlsCACertPath = "/absolute_path_to/registrar-tls-ca.crt"
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[masa]
bindAddress = ""
port = 0
expiresOn = ""
ldevidCAKeyPath = ""
ldevidCACertPath = ""
tlsKeyPath = ""
tlsCertPath = ""
tlsCACertPath = ""
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""
```

### Starting the registrar

To start the registrar server on port `12345` use the command `registrar` as following:
```bash
$ brski -c config.ini registrar
```
where the example `config.ini` file is defined as follows:

```ini
[pledge]
createdOn = ""
serialNumber = ""
nonce = ""
idevidKeyPath = ""
idevidCertPath = "/absolute_path_to/idevid.crt"
idevidCACertPath = "/absolute_path_to/idevid-ca.crt"
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[registrar]
bindAddress = "127.0.0.1"
port = 12345
tlsKeyPath = ""
tlsCertPath = "/absolute_path_to/registrar-tls.crt"
tlsCACertPath = "/absolute_path_to/registrar-tls-ca.crt"
cmsSignKeyPath = "/absolute_path_to/registrar-cms.key"
cmsSignCertPath = "/absolute_path_to/registrar-cms.crt"
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[masa]
bindAddress = "https://masa-address.com"
port = 12346
expiresOn = ""
ldevidCAKeyPath = ""
ldevidCACertPath = "/absolute_path_to/ldevid-ca.crt"
tlsKeyPath = ""
tlsCertPath = "/absolute_path_to/masa-tls.crt"
tlsCACertPath = "/absolute_path_to/masa-tls-ca.crt"
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""
```

### Starting the MASA

To start the MASA server on port `12346` use the command `masa` as following:
```bash
$ brski -c config.ini masa
```
where the example `config.ini` file is defined as follows:

```ini
[pledge]
createdOn = ""
serialNumber = ""
nonce = ""
idevidKeyPath = ""
idevidCertPath = "/absolute_path_to/idevid.crt"
idevidCACertPath = "/absolute_path_to/idevid-ca.crt"
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[registrar]
bindAddress = ""
port = 12345
tlsKeyPath = ""
tlsCertPath = "/absolute_path_to/registrar-tls.crt"
tlsCACertPath = "/absolute_path_to/registrar-tls-ca.crt"
cmsSignKeyPath = ""
cmsSignCertPath = ""
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""

[masa]
bindAddress = "127.0.0.1"
port = 12346
expiresOn = "1973-11-29T21:33:09Z"
ldevidCAKeyPath = "/absolute_path_to/ldevid-ca.key"
ldevidCACertPath = "/absolute_path_to/ldevid-ca.crt"
tlsKeyPath = "/absolute_path_to/masa-tls.key"
tlsCertPath = "/absolute_path_to/masa-tls.crt"
tlsCACertPath = "/absolute_path_to/masa-tls-ca.crt"
cmsSignKeyPath = "/absolute_path_to/masa-cms.key"
cmsSignCertPath = "/absolute_path_to/masa-cms.crt"
cmsAdditionalCertPath = ""
cmsVerifyCertPath = ""
cmsVerifyStorePath = ""
```

For detailed example of `config.ini` files and certificates pleasce check the `test` folder.
