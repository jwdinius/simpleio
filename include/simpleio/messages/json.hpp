// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

#include "simpleio/message.hpp"

namespace simpleio::messages {

/// @brief Define JsonMessageType as an nlohmann::json document.
using JsonMessageType = nlohmann::json;

/// @brief Serialize and deserialize JSON messages.
/// @details JSON messages are serialized and deserialized using nlohmann/json
/// library.
class JsonSerializer
    : public Serializer<JsonMessageType, DEFAULT_MAX_BLOB_SIZE> {
 public:
  /// @brief Serialize an nlohmann/json object into a string.
  /// @param entity, the nlohmann/json object to serialize.
  /// @return std::string, the serialized nlohmann/json object.
  /// @throw SerializerError, if an error occurs during serialization.
  std::string serialize(JsonMessageType const& entity) override {
    try {
      return entity.dump();
    } catch (nlohmann::json::exception& e) {
      throw SerializerError(e.what());
    }
  }

  /// @brief Deserialize a string into an nlohmann/json object.
  /// @param blob, the string to deserialize.
  /// @return JsonMessageType, the deserialized nlohmann/json object.
  /// @throw SerializerError, if an error occurs during deserialization.
  JsonMessageType deserialize(std::string const& blob) override {
    try {
      return nlohmann::json::parse(blob);
    } catch (nlohmann::json::exception& e) {
      throw SerializerError(e.what());
    }
  }
};

}  // namespace simpleio::messages
