add_compile_options(
  # Enable GCC static analysis if compiling in Debug mode
  # (warning, is very slow)
  $<$<AND:$<C_COMPILER_ID:GNU>,$<CONFIG:Debug>>:-fanalyzer>
)

add_library(list list.c)
target_link_libraries(list PRIVATE os log)

add_library(serialize serialize.c)
target_link_libraries(serialize PRIVATE list os)
target_compile_definitions(serialize PRIVATE _DEFAULT_SOURCE _BSD_SOURCE _XOPEN_SOURCE)

add_library(voucher voucher.c)
if (USE_VOUCHER_OPENSSL AND (NOT USE_VOUCHER_WOLFSSL))
    add_library(voucher_crypto voucher_crypto_ossl.c)
    target_link_libraries(voucher_crypto PRIVATE OpenSSL3::Crypto log os)
    target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE list voucher_crypto serialize os)
elseif (USE_VOUCHER_WOLFSSL)
    add_library(voucher_crypto voucher_crypto_wssl.c)
    target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE list voucher_crypto serialize os)
else ()
    target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE list serialize os)
endif ()

add_library(voucher_request voucher_request.c)
target_link_libraries(voucher_request PRIVATE serialize voucher os)
