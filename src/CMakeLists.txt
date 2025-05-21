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
    #transports/ip/http.cpp
    transports/ip/ip.cpp
    transports/ip/tcp.cpp
    transports/ip/tls.cpp
    transports/ip/udp.cpp
)

target_link_libraries(transports_ip
  PRIVATE
    Boost::log
    Boost::log_setup
)

#target_sources(beast_client
#  PRIVATE
#    transports/ip/http_client.cpp
#)
#
#target_sources(beast_server
#  PRIVATE
#    transports/ip/http_server.cpp
#)
#target_link_libraries(beast_server
#  PRIVATE
#    Boost::system
#)
