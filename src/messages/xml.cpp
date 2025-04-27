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

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

std::string siomsg::XmlSerializer::serialize(
    siomsg::XmlMessageType const& entity) {
  try {
    Poco::XML::DOMWriter writer;
    std::ostringstream oss;
    writer.writeNode(oss, entity);

    return oss.str();
  } catch (Poco::Exception& e) {
    throw sio::SerializationError(e.what());
  }
}

siomsg::XmlMessageType siomsg::XmlSerializer::deserialize(
    std::string const& blob) {
  try {
    std::istringstream iss(blob);
    Poco::XML::DOMParser parser;
    Poco::XML::InputSource input_source(iss);
    return parser.parse(&input_source);
  } catch (Poco::Exception& e) {
    throw sio::SerializationError(e.what());
  }
}
