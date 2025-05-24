target_sources(base
  INTERFACE
    FILE_SET HEADERS
    FILES
      #simpleio/async_queue.hpp
      simpleio/message.hpp
      #simpleio/transport.hpp
      #simpleio/worker.hpp
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

target_sources(messages_json
  PUBLIC
    FILE_SET HEADERS
    FILES
      simpleio/messages/json.hpp
)

#target_link_libraries(messages_json
#  PUBLIC
#    base
#    nlohmann_json::nlohmann_json
#)
#
#target_sources(transports_ip
#  PUBLIC
#    FILE_SET HEADERS
#    FILES
#      simpleio/transports/ip/ip.hpp
#      simpleio/transports/ip/tcp.hpp
#      simpleio/transports/ip/tls.hpp
#      simpleio/transports/ip/udp.hpp
#)
#
#target_link_libraries(transports_ip
#  PUBLIC
#    base
#    Boost::system
#    OpenSSL::SSL  # Needed b/c Boost doesn't export dependencies properly
#)
