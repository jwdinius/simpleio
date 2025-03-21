# Specify the source files
target_sources(xml_message
  PRIVATE
    xml_message.cpp
)

#target_link_libraries(my_app PRIVATE Poco::Foundation Poco::Net Poco::Util)

#target_link_libraries(xml_message
#  PRIVATE
#    #Boost::log
#    #Boost::log_setup
#    #fmt::fmt
#    #Poco::Net
#    Poco::XML
#)