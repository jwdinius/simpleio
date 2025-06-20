target_sources(base
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/async_queue.hpp
      simpleio/message.hpp
      simpleio/transport.hpp
)

target_sources(messages_http
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/messages/http.hpp
)

target_link_libraries(messages_http
  INTERFACE
    base
    Boost::system
)

target_sources(messages_json
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/messages/json.hpp
)

target_link_libraries(messages_json
  INTERFACE
    base
    nlohmann_json::nlohmann_json
)

target_sources(messages_xml
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/messages/xml.hpp
)

target_link_libraries(messages_xml
  INTERFACE
    base
    Poco::XML
)

target_sources(transports_ip
  PUBLIC
    FILE_SET HEADERS
    FILES
      simpleio/transports/ip/http.hpp
      simpleio/transports/ip/https.hpp
      simpleio/transports/ip/ip.hpp
      simpleio/transports/ip/tcp.hpp
      simpleio/transports/ip/tls.hpp
      simpleio/transports/ip/udp.hpp
)

target_link_libraries(transports_ip
  PUBLIC
    base
    Boost::system
    OpenSSL::SSL  # Needed b/c Boost doesn't export dependencies properly
)

target_sources(worker
  INTERFACE
    FILE_SET HEADERS
    FILES
      simpleio/worker.hpp
)

target_link_libraries(worker
  INTERFACE
    base
)
