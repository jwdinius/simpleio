# Enable testing
enable_testing()

# Find GoogleTest package
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add the test executables
add_executable(test_messages_http test_messages_http.cpp)
target_link_libraries(test_messages_http
  PRIVATE
    ${GTEST_LIBRARIES}
    pthread
    ${PROJECT_NAME}::messages::http
)
add_test(NAME test_messages_http COMMAND test_messages_http)

add_executable(test_messages_json test_messages_json.cpp)
target_link_libraries(test_messages_json
  PRIVATE
    ${GTEST_LIBRARIES}
    pthread
    ${PROJECT_NAME}::messages::json
)
add_test(NAME test_messages_json COMMAND test_messages_json)

add_executable(test_messages_xml test_messages_xml.cpp)
target_link_libraries(test_messages_xml
  PRIVATE
    ${GTEST_LIBRARIES}
    pthread
    ${PROJECT_NAME}::messages::xml
)
add_test(NAME test_messages_xml COMMAND test_messages_xml)

# Install tls certificates to the build directory under the certs directory
set(CERTS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/certs)
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/certs_path.h"
  CONTENT "inline constexpr char CERTS_PATH[] = \"${CERTS_PATH}\";  //NOLINT"
)

add_executable(test_transports_ip test_transports_ip.cpp)  # Adjust the path to your test file
target_include_directories(test_transports_ip
  PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(test_transports_ip
  PRIVATE
    ${GTEST_LIBRARIES}
    pthread
    Boost::system
    Boost::log
    Boost::log_setup
    ${PROJECT_NAME}::transports::ip
)
add_test(NAME test_transports_ip COMMAND test_transports_ip)
set_tests_properties(test_transports_ip PROPERTIES TIMEOUT 10)

add_executable(test_worker test_worker.cpp)
target_link_libraries(test_worker
  PRIVATE
    ${GTEST_LIBRARIES}
    pthread
    ${PROJECT_NAME}::worker
)
add_test(NAME test_worker COMMAND test_worker)
