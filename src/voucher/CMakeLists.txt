add_compile_options(
  # Enable GCC static analysis if compiling in Debug mode
  # (warning, is very slow)
  $<$<AND:$<C_COMPILER_ID:GNU>,$<CONFIG:Debug>>:-fanalyzer>
)

if (USE_VOUCHER_OPENSSL AND (NOT USE_VOUCHER_WOLFSSL))
    add_library(voucher serialize.c keyvalue.c array.c crypto_ossl.c voucher.c request.c)
    target_link_libraries(voucher PRIVATE OpenSSL3::Crypto os log jsmn::jsmn)
elseif (USE_VOUCHER_WOLFSSL)
    add_library(voucher serialize.c keyvalue.c array.c crypto_wssl.c voucher.c request.c)
    target_link_libraries(voucher PRIVATE os log jsmn::jsmn)
else ()
    message(FATAL_ERROR "No crypto library option defined")
endif ()

target_compile_definitions(voucher PRIVATE _DEFAULT_SOURCE _BSD_SOURCE _XOPEN_SOURCE)
set_target_properties(voucher PROPERTIES PUBLIC_HEADER "src/voucher/array.h;src/voucher/voucher.h")
