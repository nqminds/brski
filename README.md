[![GitHub release (latest stable SemVer)](https://img.shields.io/github/v/release/nqminds/brski?label=stable&logo=github&sort=semver)](https://github.com/nqminds/brski/releases)
[![Build Passing](https://github.com/nqminds/brski/actions/workflows/codeql.yml/badge.svg)](https://github.com/nqminds/brski/actions/workflows/codeql.yml)
[![GitHub license](https://img.shields.io/github/license/nqminds/brski)](https://github.com/nqminds/brski/blob/main/LICENSE)
![CMake](https://img.shields.io/badge/CMake-%23008FBA.svg?logo=cmake&logoColor=white)
![C11](https://img.shields.io/badge/C11-informational.svg?logo=c)
# Bootstrapping Remote Secure Key Infrastructure - reference implementation

The Bootstrapping Remote Secure Key Infrastructure (BRSKI) protocol provides a solution for secure zero-touch (automated) bootstrap of new (unconfigured) devices that are called "pledges". Pledges have an Initial Device Identifier (IDevID) installed in them at the factory.

For more information on the BRSKI protocol, please check the [RFC8995](https://www.rfc-editor.org/rfc/rfc8995.html).

This repo provides a reference implementation for the BRSKI protocol in `C` language.

## Features
1. Voucher artifact implementation as per [RFC8366](https://www.rfc-editor.org/info/rfc8366),
2. Pledge-Registrar voucher request implementation with CMS signatures,
3. Registrar-MASA voucher request implementation with CMS signatures,
4. MASA-Pledge voucher request implementation with CMS signatures and
5. CMS signatures dependency on OpenSSL or WolfSSL libraries.

## Compile & Build

Compiling the BRSKI voucher library is done with CMake.

### Dependencies

The BRSKI voucher library requires OpenSSL3. You can either:
  - Install OpenSSL3 yourself
    (on Ubuntu 22.04 (Jammy) or Debian 12 (Bookworm) or later, you can just run `sudo apt install libssl-dev`)
  - The BRSKI CMake config file allows also downloading and compiling the OpenSSL library from source.
    Change the option `BUILD_OPENSSL3_LIB` to `ON` in `CMakeLists.txt` file to force CMake to download and compile the OpenSSL library.

### Configure

If you have CMake v3.22+, you can use the following `cmake-presets` to compile BRSKI voucher libray and demo pledge, registrar, and masa tools:

```bash
cmake --list-presets # list all available presets
cmake --preset linux # configure the BRSKI voucher library for Linux
cmake --build --preset linux -j4 # build BRSKI for Linux using 4 threads
ctest --preset linux # test BRSKI for Linux
```
For older versions of CMake, or for manual configuration, please see the next headings for more details.

Configure `cmake` in the `build/` directory by running the following:

```bash
# or for old versions of cmake, do: mkdir build/ && cd build/ && cmake ..
cmake -S . -B build
```

The configure stage will download some of the BRSKI dependencies, so this may take a while.

### Building

To build, you can then run:

```bash
# or for old versions of cmake, do: cd build/ && make
cmake --build build/
```

or to built on multiple core run:

```bash
cmake --build build/ -j4
```

`-j4` means 4 jobs/threads, replace `4` with the amount of cores you want to use, equivalent to `make -j4`.

After succesful compilation the binary will be located in `./build/src` folder.


## Running

To run the BRSKI binary with the configuration file `dev-config.ini` located in `./build` folder use:

```bash
./build/src/brski -c ./build/dev-config.ini command
```

To enable verbose debug mode use:

```bash
./build/src/brski -c ./build/dev-config.ini command -ddddd
```
where `command` is one of the commands to execute. For more details see [examples](./docs/usage.md).

You can also look at [Running with test examples](#running-with-test-examples)
for examples that use pregenerated test certificates.

## Installing

To install the library and the BRSKI binary, and config use:
```bash
cmake --build --preset linux --target install
```

To install in a custom folder one needs to set the install prefix before running the above command with:
```bash
cmake -DCMAKE_INSTALL_PREFIX:PATH=/custom_folder_path --preset linux
```

The cmake installs the following artifacts:
- `/../bin/brksi` - BRSKI tool
- `/../etc/brski/config.ini` - BRSKI tool config file
- `/../lib/libvoucher.a` - voucher static library
- `/../include/voucher/array.h` - the array helper include file
- `/../include/voucher/voucher.h` - the voucher API include file

## Testing

To compile the tests use:

```bash
cmake -B build/ -S . # configure CMAKE
cmake --build build/ -j4 # or make -j4
cmake --build build/ --target test -j4 # or 'make test'
```

To run each test individually, the test binaries are located in `./build/preset_name/tests` folder.

### Running with test examples

Additionally, you can manually setup a MASA and registrar server on `localhost`
using some test certificates.

 1. Run the tests once using `ctest --preset linux` (or equivalent).
    This will create some example test certificates using the
    `generate_test_certs` test.
 2. Start the MASA server using:
    `./build/linux/src/brski/brski -c ./build/linux/tests/brski/test-config.ini masa`
 3. Start the registrar server using:
    `./build/linux/src/brski/brski -c ./build/linux/tests/brski/test-config.ini registrar`
 4. Send a pledge request to the registrar server using:

    ```console
    user@pc:~/brski (main)$ ./build/linux/src/brski/brski -c ./build/linux/tests/brski/test-config.ini preq
    Pledge voucher request to 127.0.0.1:12345
    2023-06-13 14:25:17.642  INFO  pledge_request.cpp:68: Request pledge voucher from /.well-known/brski/requestvoucher
    2023-06-13 14:25:17.645  INFO  httplib_wrapper.cpp:245: Post request to 127.0.0.1:12345/.well-known/brski/requestvoucher
    MIIBRjCB7aADAgECAgEBMAoGCCqGSM49BAMCMCExCzAJBgNVBAYTAklFMRIwEAYDVQQDDAlsZGV2aWQtY2EwHhcNMjMwNjEzMTMyNTE3WhcNMjMwNjI3MjAyMTI0WjAqMQswCQYDVQQGEwJJRTEbMBkGA1UEAwwScGlubmVkLWRvbWFpbi1tZXRhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BCjjmrshoAmneAJd8/D2iIPCkBbbcGoSX0fcvoxUAjCNIUyC9mhHAe8pAV2MFiJdngshvaXyhpYHm0iC4Qi36MNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiEA1gT++JfiP522ddkCTKtzOyU8MOFa8+u4owvWPK+O2nkCIG/hDl1nFzDWQMIthyXxOUinL7crA9w2ZCW/6pwnhYX2
    ```

    If successful, the returned ASN1 `pinned-domain-cert` in the voucher will be
    printed in base64 to stdout.

## Developer Documentation

1. Voucher artifact [API](./docs/voucher.md).
2. BRSKI voucher request [API](./docs/brski.md).
3. Array helpers [API](./docs/array.md).
4. Usage [examples](./docs/usage.md).
