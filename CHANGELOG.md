# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🚀 Features

* brski tool to demonstrate the Registrar and MASA functionalities

#### voucher

* add `not_after_absolute` field to `struct crypto_cert_meta`.
  Unlike the existing `not_after` field, which represents an offset from the
  current time, the `not_after_absolute` field represents an absolute time.
  It can be set to `"99991231235959Z"` for a
  [long-lived pledge certificate][rfc8995#2.6.2].

[rfc8995#2.6.2]: https://www.rfc-editor.org/rfc/rfc8995.html#name-infinite-lifetime-of-idevid

#### Build

* add `BUILD_JSMN` CMake option. Set this to `OFF` in case you want to use
  your system's [jsmn](https://github.com/zserge/jsmn) lib, instead of
  downloading it automatically.

### Changed

#### voucher

**The voucher ABI has breaking changes**.

## [0.2.0] - 2023-03-27
### Added
* Voucher artifact implementation as per [RFC8366](https://www.rfc-editor.org/info/rfc8366),
* Pledge-Registrar voucher request implementation with CMS signatures,
* Registrar-MASA voucher request implementation with CMS signatures,
* MASA-Pledge voucher request implementation with CMS signatures and
* CMS signatures dependency on OpenSSL or WolfSSL libraries.
