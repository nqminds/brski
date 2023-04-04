add_library(pledge_utils pledge_utils.c)
target_link_libraries(pledge_utils PRIVATE array voucher serialize os log)

add_library(pledge_request pledge_request.cpp)
target_link_libraries(pledge_request PRIVATE https_client array voucher serialize os log)
