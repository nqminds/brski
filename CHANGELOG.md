# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🚀 Features

* brski tool to demonstrate the Registrar and MASA functionalities

### Removed

* Drop support for compiling brski with CMake v3.14.
  CMake v3.15 is now the minimum required version of CMake.

## [0.2.0] - 2023-03-27
### Added
* Voucher artifact implementation as per [RFC8366](https://www.rfc-editor.org/info/rfc8366),
* Pledge-Registrar voucher request implementation with CMS signatures,
* Registrar-MASA voucher request implementation with CMS signatures,
* MASA-Pledge voucher request implementation with CMS signatures and
* CMS signatures dependency on OpenSSL or WolfSSL libraries.
