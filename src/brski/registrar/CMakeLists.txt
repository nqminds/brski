add_library(registrar_api registrar_api.cpp)
target_link_libraries(registrar_api PRIVATE os log config array voucher)

add_library(registrar_server registrar_server.cpp)
target_link_libraries(registrar_server PRIVATE registrar_api os log https_server)
