cmake_minimum_required (VERSION 2.6)
project (SecurityTools)

add_subdirectory(common)
add_subdirectory(sslscan)
# Not working with the latest libssh
#add_subdirectory(sshscan)
