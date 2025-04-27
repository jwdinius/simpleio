// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <Poco/DOM/AutoPtr.h>
#include <Poco/DOM/Document.h>

#include <memory>
#include <string>

#include "simpleio/message.hpp"

namespace simpleio::messages {

/// @brief Define XmlMessageType as a Poco XML Document.
/// @details XML messages use Poco's XML library to handle XML documents.
using XmlMessageType = Poco::XML::AutoPtr<Poco::XML::Document>;

/// @brief Serialize and deserialize XML messages.
/// @details XML messages are serialized and deserialized using Poco's XML
/// library.
class XmlSerializer : public SerializationStrategy<XmlMessageType> {
 public:
  /// @brief Serialize a Poco XML Document into a string.
  /// @param entity, the Poco XML Document to serialize.
  /// @return std::string, the serialized XML Document.
  /// @throw SerializationError, if an error occurs during serialization.
  std::string serialize(XmlMessageType const& entity) override;

  /// @brief Deserialize a string into a Poco XML Document.
  /// @param blob, the string to deserialize.
  /// @return XmlMessageType, the deserialized XML Document.
  /// @throw SerializationError, if an error occurs during deserialization.
  XmlMessageType deserialize(std::string const& blob) override;
};

}  // namespace simpleio::messages
