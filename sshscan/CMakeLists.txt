set(LIBSSH libssh-0.4.1)

include_directories(
    ${CMAKE_SOURCE_DIR}/external/tclap-1.2.0
    ${CMAKE_SOURCE_DIR}/external/${LIBSSH}/include
    ${CMAKE_SOURCE_DIR}/external/${LIBSSH}/build
)
link_directories(
    ${CMAKE_SOURCE_DIR}/external/${LIBSSH}/build/libssh
)

add_executable(sshscan
    sshscan.cpp
)
target_link_libraries(sshscan
    common
    ssh
    crypto
    z
)
