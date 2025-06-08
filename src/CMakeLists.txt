target_sources(transports_ip
  PRIVATE
    transports/ip/ip.cpp
)

target_link_libraries(transports_ip
  PRIVATE
    Boost::log
    Boost::log_setup
)
