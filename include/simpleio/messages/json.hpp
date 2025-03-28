// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <memory>
#include <nlohmann/json.hpp>
#include <vector>

#include "simpleio/message.hpp"

namespace simpleio::messages {

/// @brief Define XmlMessageType as a Poco XML Document.
/// @details XML messages use Poco's XML library to handle XML documents.
using JsonMessageType = nlohmann::json;

/// @brief Serialize and deserialize JSON messages.
/// @details JSON messages are serialized and deserialized using nlohmann/json
/// library.
class JsonSerializer : public SerializationStrategy<JsonMessageType> {
 public:
  /// @brief Serialize an nlohmann/json object into a byte vector.
  /// @param entity, the nlohmann/json object to serialize.
  /// @return std::vector<std::byte>, the serialized nlohmann/json object.
  /// @throw SerializationError, if an error occurs during serialization.
  std::vector<std::byte> serialize(JsonMessageType const& entity) override;

  /// @brief Deserialize a byte vector into an nlohmann/json object.
  /// @param blob, the byte vector to deserialize.
  /// @return JsonMessageType, the deserialized nlohmann/json object.
  /// @throw SerializationError, if an error occurs during deserialization.
  JsonMessageType deserialize(std::vector<std::byte> const& blob) override;
};

}  // namespace simpleio::messages
