include_directories(
    ${CMAKE_SOURCE_DIR}/external/tclap-1.2.0/include
    ${CMAKE_SOURCE_DIR}/common
)

#find_package(openssl)

add_executable(sslscan sslscan.cpp)
target_link_libraries(sslscan common ssl crypto)
