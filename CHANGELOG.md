# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🚀 Features

* brski tool to demonstrate the Registrar and MASA functionalities

#### Build

* add `BUILD_JSMN` CMake option. Set this to `OFF` in case you want to use
  your system's [jsmn](https://github.com/zserge/jsmn) lib, instead of
  downloading it automatically.

## [0.2.0] - 2023-03-27
### Added
* Voucher artifact implementation as per [RFC8366](https://www.rfc-editor.org/info/rfc8366),
* Pledge-Registrar voucher request implementation with CMS signatures,
* Registrar-MASA voucher request implementation with CMS signatures,
* MASA-Pledge voucher request implementation with CMS signatures and
* CMS signatures dependency on OpenSSL or WolfSSL libraries.
