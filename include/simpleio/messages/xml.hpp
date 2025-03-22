// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <Poco/DOM/AutoPtr.h>
#include <Poco/DOM/Document.h>

#include <memory>
#include <vector>

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
  /// @brief Serialize a Poco XML Document into a byte vector.
  /// @param entity, the Poco XML Document to serialize.
  /// @return std::vector<std::byte>, the serialized XML Document.
  /// @throw SerializationError, if an error occurs during serialization.
  std::vector<std::byte> serialize(XmlMessageType const& entity) override;

  /// @brief Deserialize a byte vector into a Poco XML Document.
  /// @param blob, the byte vector to deserialize.
  /// @return XmlMessageType, the deserialized XML Document.
  /// @throw SerializationError, if an error occurs during deserialization.
  XmlMessageType deserialize(std::vector<std::byte> const& entity) override;
};

}  // namespace simpleio::messages
