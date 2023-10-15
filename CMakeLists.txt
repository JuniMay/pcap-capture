cmake_minimum_required(VERSION 3.10)
project(pcap_capture)

set(CMAKE_C_STANDARD 11)

find_library(PCAP_LIBRARY pcap)
add_executable(pcap_capture src/main.c)
target_link_libraries(pcap_capture ${PCAP_LIBRARY})
