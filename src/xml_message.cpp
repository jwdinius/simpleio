#include <cstring>
#include <iostream>
#include <sstream>

#include <Poco/DOM/DOMWriter.h>
#include <Poco/DOM/DOMParser.h>
#include <Poco/XML/XMLWriter.h>
#include <Poco/SAX/InputSource.h>

#include "simpleio/xml_message/xml_message.hpp"

namespace sioxml = simpleio::xml_message;

std::vector<std::byte> sioxml::XmlSerializer::serialize(sioxml::MessageType const& entity)
{
    Poco::XML::DOMWriter writer;
    std::ostringstream oss;
    writer.writeNode(oss, entity);
    
    std::string xml_string = oss.str();
    size_t xml_size = xml_string.size();
    std::vector<std::byte> blob(xml_size);
    std::memcpy(blob.data(), xml_string.data(), xml_size);

    return blob;
}

sioxml::MessageType sioxml::XmlSerializer::deserialize(std::vector<std::byte> const& entity)
{
    std::string xml_string(reinterpret_cast<char const*>(entity.data()), entity.size());
    std::istringstream iss(xml_string);
    Poco::XML::DOMParser parser;
    Poco::XML::InputSource input_source(iss);
    sioxml::MessageType doc = parser.parse(&input_source);
    return doc;
}

// XmlMessage constructor (construction)
sioxml::XmlMessage::XmlMessage(sioxml::MessageType&& entity, std::shared_ptr<XmlSerializer> strategy)
: Message<sioxml::MessageType, sioxml::MaxBlobSize>(std::move(entity), strategy)
{}

// XmlMessage constructor (reconstruction)
sioxml::XmlMessage::XmlMessage(std::vector<std::byte>&& bytes, std::shared_ptr<XmlSerializer> strategy)
: Message<sioxml::MessageType, sioxml::MaxBlobSize>(std::move(bytes), strategy)
{}
