target_sources(messages_xml
  PRIVATE
    messages/xml.cpp
)

target_sources(messages_json
  PRIVATE
    messages/json.cpp
)

target_sources(transports_ip
  PRIVATE
    transports/tcp.cpp
    transports/tls.cpp
    transports/udp.cpp
)

target_link_libraries(transports_ip
  PRIVATE
    Boost::log
    Boost::log_setup
)
