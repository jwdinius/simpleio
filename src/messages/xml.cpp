// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/messages/xml.hpp"

#include <Poco/DOM/DOMParser.h>
#include <Poco/DOM/DOMWriter.h>
#include <Poco/SAX/InputSource.h>
#include <Poco/XML/XMLWriter.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

std::vector<std::byte> siomsg::XmlSerializer::serialize(
    siomsg::XmlMessageType const& entity) {
  try {
    Poco::XML::DOMWriter writer;
    std::ostringstream oss;
    writer.writeNode(oss, entity);

    std::string xml_string = oss.str();
    size_t xml_size = xml_string.size();
    std::vector<std::byte> blob(xml_size);
    std::memcpy(blob.data(), xml_string.data(), xml_size);

    return blob;
  } catch (Poco::Exception& e) {
    throw sio::SerializationError(e.what());
  }
}

siomsg::XmlMessageType siomsg::XmlSerializer::deserialize(
    std::vector<std::byte> const& blob) {
  try {
    std::string xml_string(reinterpret_cast<char const*>(blob.data()),
                           blob.size());
    std::istringstream iss(xml_string);
    Poco::XML::DOMParser parser;
    Poco::XML::InputSource input_source(iss);
    return parser.parse(&input_source);
  } catch (Poco::Exception& e) {
    throw sio::SerializationError(e.what());
  }
}
