if (BUILD_ONLY_DOCS)
else()
    include(FetchContent)
    FetchContent_Declare(cpr
        URL https://github.com/libcpr/cpr/archive/refs/tags/1.9.5.tar.gz
        URL_HASH SHA3_256=bea98952db1fe1f45f8d7cf88af98ac67178072722fef33c677f6956690fb489
        DOWNLOAD_NAME "cpr-1.9.5.tar.gz"
        DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default dir
    )
endif()
