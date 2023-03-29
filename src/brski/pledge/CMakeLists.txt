add_library(pledge_utils pledge_utils.c)
target_link_libraries(pledge_utils PRIVATE voucher serialize os log)
