file(COPY "${CMAKE_CURRENT_LIST_DIR}/brski-test-certs" DESTINATION "${CMAKE_BINARY_DIR}/tests/brski")

set(TEST_CONFIG_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${TEST_CONFIG_INI_PATH}" @ONLY)

set(TEST_CONFIG_ADD_INI_PATH "${CMAKE_BINARY_DIR}/tests/brski/test-config-add.ini")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config-add.ini.in" "${TEST_CONFIG_ADD_INI_PATH}" @ONLY)

add_cmocka_test(test_pledge_utils
  SOURCES test_pledge_utils.c
  LINK_LIBRARIES config pledge_utils os log cmocka::cmocka
)
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_INI_PATH="${TEST_CONFIG_INI_PATH}")
target_compile_definitions(test_pledge_utils PRIVATE TEST_CONFIG_ADD_INI_PATH="${TEST_CONFIG_ADD_INI_PATH}")

#openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
#  -keyout pledge-cms.key -out pledge-cms.crt -subj "/CN=pledge-cms.com" \
#  -addext "subjectAltName=DNS:pledge-cms.com,DNS:www.pledge-cms.net,IP:10.0.1.1"
