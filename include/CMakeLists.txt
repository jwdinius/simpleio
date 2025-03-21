target_sources(${PROJECT_NAME}
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/async_queue.hpp
      simpleio/message.hpp
      simpleio/transport.hpp
)

target_link_libraries(${PROJECT_NAME}
  INTERFACE
    Microsoft.GSL::GSL
)

target_sources(xml_message
  PUBLIC
    FILE_SET HEADERS
    FILES
      simpleio/xml_message/xml_message.hpp
)

target_link_libraries(xml_message
  PUBLIC
    ${PROJECT_NAME}
    Poco::XML
)

target_sources(network_transport
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/network_transport/tcp.hpp
      simpleio/network_transport/tls.hpp
      simpleio/network_transport/udp.hpp
)

target_link_libraries(network_transport
  INTERFACE
    ${PROJECT_NAME}
    Boost::system
    Boost::log
    OpenSSL::SSL  # Needed b/c Boost doesn't export dependencies properly
    OpenSSL::Crypto
)