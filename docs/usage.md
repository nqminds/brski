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
nonce = "QlJTS0kgcHJvdG9jb2wgc2VydmVyL2NsaWVudCBpbXBsZW1lbnRhdGlvbi4="
cmsSignKeyPath = "/absolute_path_to/pledge-cms.key"
cmsSignCertPath = "/absolute_path_to/pledge-cms.crt"
cmsAdditionalCertPath = ""

[registrar]
bindAddress = "0.0.0.0"
port = 12345
tlsKeyPath = "/absolute_path_to/registrar-tls.key"
tlsCertPath = "/absolute_path_to/registrar-tls.crt"
```

The `config.ini` pledge keys used for the export functionality are:

- `createdOn` (yang time value),
- `serialNumber`,
- `nonce` (base64),
- `cmsSignKeyPath` (path to private key to sign the CMS) and
- `cmsSignCertPath` (path to certificate).

The `config.ini` registrar keys used for the export functionality are:
- `tlsKeyPath` (path to registrar TLS private key) and
- `tlsCertPath` (path to registrar TLS certificate).