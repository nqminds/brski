add_library(registrar_api registrar_api.cpp)

add_library(registrar_server registrar_server.cpp)
target_link_libraries(registrar_server PRIVATE registrar_api os log https_server)
