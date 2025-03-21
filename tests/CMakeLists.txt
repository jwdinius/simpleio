# Enable testing
enable_testing()

# Find GoogleTest package
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add the test executable
add_executable(test_xml_message test_xml_message.cpp)  # Adjust the path to your test file
target_link_libraries(test_xml_message ${GTEST_LIBRARIES} pthread ${PROJECT_NAME}::xml_message)
add_test(NAME test_xml_message COMMAND test_xml_message)

# Install tls certificates to the build directory under the certs directory
set(CERTS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/certs)
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/certs_path.h"
  CONTENT "inline constexpr char CERTS_PATH[] = \"${CERTS_PATH}\";"
)

add_executable(test_network_transport test_network_transport.cpp)  # Adjust the path to your test file
target_include_directories(test_network_transport PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_network_transport ${GTEST_LIBRARIES} pthread Boost::system Boost::log Boost::log_setup ${PROJECT_NAME}::network_transport)
add_test(NAME test_network_transport COMMAND test_network_transport)
set_tests_properties(test_network_transport PROPERTIES TIMEOUT 10)