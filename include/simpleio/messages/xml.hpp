// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <Poco/DOM/AutoPtr.h>
#include <Poco/DOM/DOMParser.h>
#include <Poco/DOM/DOMWriter.h>
#include <Poco/DOM/Document.h>
#include <Poco/SAX/InputSource.h>
#include <Poco/XML/XMLWriter.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "simpleio/message.hpp"

namespace simpleio::messages {

/// @brief Define XmlMessageType as a Poco XML Document.
/// @details XML messages use Poco's XML library to handle XML documents.
using XmlMessageType = Poco::XML::AutoPtr<Poco::XML::Document>;

/// @brief Serialize and deserialize XML messages.
/// @details XML messages are serialized and deserialized using Poco's XML
/// library.
class XmlSerializer : public Serializer<XmlMessageType, DEFAULT_MAX_BLOB_SIZE> {
 public:
  /// @brief Serialize a Poco XML Document into a string.
  /// @param entity, the Poco XML Document to serialize.
  /// @return std::string, the serialized XML Document.
  /// @throw SerializerError, if an error occurs during serialization.
  std::string serialize(XmlMessageType const& entity) override {
    try {
      Poco::XML::DOMWriter writer;
      std::ostringstream oss;
      writer.writeNode(oss, entity);

      return oss.str();
    } catch (Poco::Exception& e) {
      throw SerializerError(e.what());
    }
  }

  /// @brief Deserialize a string into a Poco XML Document.
  /// @param blob, the string to deserialize.
  /// @return XmlMessageType, the deserialized XML Document.
  /// @throw SerializerError, if an error occurs during deserialization.
  XmlMessageType deserialize(std::string const& blob) override {
    try {
      std::istringstream iss(blob);
      Poco::XML::DOMParser parser;
      Poco::XML::InputSource input_source(iss);
      return parser.parse(&input_source);
    } catch (Poco::Exception& e) {
      throw SerializerError(e.what());
    }
  }
};

}  // namespace simpleio::messages
