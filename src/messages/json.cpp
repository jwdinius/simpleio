// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/messages/json.hpp"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

std::vector<std::byte> siomsg::JsonSerializer::serialize(
    siomsg::JsonMessageType const& entity) {
  try {
    std::string json_string = entity.dump();
    size_t json_size = json_string.size();
    std::vector<std::byte> blob(json_size);
    std::memcpy(blob.data(), json_string.data(), json_size);

    return blob;
  } catch (nlohmann::json::exception& e) {
    throw sio::SerializationError(e.what());
  }
}

siomsg::JsonMessageType siomsg::JsonSerializer::deserialize(
    std::vector<std::byte> const& blob) {
  try {
    std::string json_string(reinterpret_cast<char const*>(blob.data()),
                            blob.size());
    return nlohmann::json::parse(json_string);
  } catch (nlohmann::json::exception& e) {
    throw sio::SerializationError(e.what());
  }
}
