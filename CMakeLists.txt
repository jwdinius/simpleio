cmake_minimum_required(VERSION 3.23)
project(simpleio CXX)

set(CMAKE_CXX_STANDARD 17)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.74 REQUIRED COMPONENTS system log log_setup)
find_package(Microsoft.GSL 4 REQUIRED)
find_package(nlohmann_json 3.10 REQUIRED)
find_package(Poco 1.11 REQUIRED COMPONENTS Net XML)
find_package(OpenSSL 3 REQUIRED)

# Base classes
add_library(base INTERFACE)
add_library(${PROJECT_NAME}::base ALIAS base)

# Message classes
add_library(messages_xml SHARED)
add_library(${PROJECT_NAME}::messages::xml ALIAS messages_xml)

add_library(messages_json SHARED)
add_library(${PROJECT_NAME}::messages::json ALIAS messages_json)

# Transport classes
add_library(transports_ip SHARED)
add_library(${PROJECT_NAME}::transports::ip ALIAS transports_ip)

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(tests)
