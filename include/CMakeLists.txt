target_sources(base
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/async_queue.hpp
      simpleio/message.hpp
      simpleio/transport.hpp
)

target_link_libraries(base
  INTERFACE
    Microsoft.GSL::GSL
)

target_sources(messages_xml
  PUBLIC
    FILE_SET HEADERS
    FILES
      simpleio/messages/xml.hpp
)

target_link_libraries(messages_xml
  PUBLIC
    base
    Poco::XML
)

target_sources(transports_ip
  PUBLIC
    FILE_SET HEADERS
    FILES
      simpleio/transports/tcp.hpp
      simpleio/transports/tls.hpp
      simpleio/transports/udp.hpp
)

target_link_libraries(transports_ip
  PUBLIC
    base
    Boost::system
    OpenSSL::SSL  # Needed b/c Boost doesn't export dependencies properly
)