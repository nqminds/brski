add_compile_options(
  # Enable GCC static analysis if compiling in Debug mode
  # (warning, is very slow)
  $<$<AND:$<C_COMPILER_ID:GNU>,$<CONFIG:Debug>>:-fanalyzer>
)

if (USE_VOUCHER_OPENSSL AND (NOT USE_VOUCHER_WOLFSSL))
    add_library(crypto OBJECT crypto_ossl.c)
    target_link_libraries(crypto PRIVATE OpenSSL3::Crypto os log)

    add_library(voucher serialize.c keyvalue.c array.c voucher.c request.c)
    target_link_libraries(voucher PRIVATE crypto os jsmn::jsmn log)
elseif (USE_VOUCHER_WOLFSSL)
    add_library(voucher serialize.c keyvalue.c array.c crypto_wssl.c voucher.c request.c)
    target_link_libraries(voucher PRIVATE os jsmn::jsmn log)
else ()
    message(FATAL_ERROR "No crypto library option defined")
endif ()

target_compile_definitions(voucher PRIVATE _DEFAULT_SOURCE _BSD_SOURCE _XOPEN_SOURCE)
set_target_properties(voucher PROPERTIES PUBLIC_HEADER "src/voucher/array.h;src/voucher/voucher.h")
