add_library(registrar_routes registrar_routes.cpp)

add_library(registrar_server registrar_server.cpp)
target_link_libraries(registrar_server PRIVATE registrar_routes os log https_server)
