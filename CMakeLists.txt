cmake_minimum_required(VERSION 3.26)



project(ids)
set(CMAKE_CXX_STANDARD 17)
include(FindPCAP.cmake)
set(CMAKE_CXX_FLAGS "-lpcap")
set(SOURCE_FILES main.cpp)
add_executable(ids main.cpp
        headers/filters.h
        headers/process_packets.h
        headers/packet_headers.h
        dissection/dissection.h
        dissection/tcp/tcp_dissect.h
        dissection/tcp/tcp_dissect.cpp
        protocols/http/http.h
        protocols/http/http.cpp)
target_compile_options(ids  PRIVATE -lpcap)
target_include_directories(ids PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/headers")
target_link_libraries(ids PRIVATE libpcap)


