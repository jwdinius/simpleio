cmake_minimum_required(VERSION 3.23)
project(taktile CXX)

set(CMAKE_CXX_STANDARD 17)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.74 REQUIRED COMPONENTS system log log_setup)
find_package(fmt 8 REQUIRED)
find_package(Microsoft.GSL 4 REQUIRED)
find_package(Poco 1.11 REQUIRED COMPONENTS Net XML)
find_package(OpenSSL 3 REQUIRED)

# Base classes
add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

# Message classes
add_library(xml_message SHARED)
add_library(${PROJECT_NAME}::xml_message ALIAS xml_message)

# Transport classes
add_library(network_transport INTERFACE)
add_library(${PROJECT_NAME}::network_transport ALIAS network_transport)

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(tests)