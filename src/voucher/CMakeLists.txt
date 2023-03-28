if (C_COMPILER_SUPPORTS_ANALYZER)
  add_compile_options(
    # Enable GCC static analysis if compiling in Debug mode
    # (warning, is very slow)
    $<$<AND:$<C_COMPILER_ID:GNU>,$<CONFIG:Debug>>:-fanalyzer>
  )
endif()

add_library(array OBJECT array.c)
target_link_libraries(array PRIVATE os log)

add_library(keyvalue OBJECT keyvalue.c)
target_link_libraries(keyvalue PRIVATE os log)

add_library(serialize OBJECT serialize.c)
target_link_libraries(serialize PRIVATE os log)
target_compile_definitions(serialize PRIVATE _DEFAULT_SOURCE _BSD_SOURCE _XOPEN_SOURCE)

if (USE_VOUCHER_OPENSSL AND (NOT USE_VOUCHER_WOLFSSL))
    add_library(crypto OBJECT crypto_ossl.c)
    target_link_libraries(crypto PRIVATE os log OpenSSL3::Crypto)
elseif (USE_VOUCHER_WOLFSSL)
    add_library(crypto OBJECT crypto_wssl.c)
    target_link_libraries(crypto PRIVATE os log)
else ()
    message(FATAL_ERROR "No crypto library option defined")
endif ()

add_library(request OBJECT request.c)
target_link_libraries(request PRIVATE os log)

add_library(voucher voucher.c)
target_link_libraries(voucher PRIVATE request crypto array serialize keyvalue os jsmn::jsmn log)
target_compile_definitions(voucher PRIVATE _DEFAULT_SOURCE _BSD_SOURCE _XOPEN_SOURCE)
set_target_properties(voucher PROPERTIES PUBLIC_HEADER "src/voucher/array.h;src/voucher/voucher.h")
