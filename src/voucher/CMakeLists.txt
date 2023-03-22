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

if (USE_VOUCHER_OPENSSL AND (NOT USE_VOUCHER_WOLFSSL))
    add_library(voucher crypto_ossl.c voucher.c request.c)
    target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE OpenSSL3::Crypto list serialize os log)
elseif (USE_VOUCHER_WOLFSSL)
    add_library(voucher crypto_wssl.c voucher.c request.c)
    target_link_libraries(voucher PUBLIC jsmn::jsmn PRIVATE list serialize os log)
else ()
    message(FATAL_ERROR "No crypto library option defined")
endif ()

set_target_properties(voucher PROPERTIES PUBLIC_HEADER "src/voucher/list.h;src/voucher/voucher.h")
