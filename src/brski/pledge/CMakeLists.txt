add_library(pledge_utils pledge_utils.cpp)
target_link_libraries(pledge_utils PRIVATE voucher os log)
