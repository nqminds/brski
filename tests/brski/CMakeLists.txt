file(COPY "${CMAKE_CURRENT_LIST_DIR}/brski-test-certs" DESTINATION "${CMAKE_BINARY_DIR}/tests/brski")
configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${CMAKE_BINARY_DIR}/tests/brski/test-config.ini" @ONLY)

#openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
#  -keyout pledge-cms.key -out pledge-cms.crt -subj "/CN=pledge-cms.com" \
#  -addext "subjectAltName=DNS:pledge-cms.com,DNS:www.pledge-cms.net,IP:10.0.1.1"
