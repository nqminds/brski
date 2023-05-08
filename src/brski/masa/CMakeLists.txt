add_library(masa_api masa_api.cpp)
target_link_libraries(masa_api PRIVATE os log config array voucher)

add_library(masa_server masa_server.cpp)
target_link_libraries(masa_server PRIVATE masa_api os log https_server)
