// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/messages/json.hpp"

#include <nlohmann/json.hpp>
#include <string>

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

std::string siomsg::JsonSerializer::serialize(
    siomsg::JsonMessageType const& entity) {
  try {
    return entity.dump();
  } catch (nlohmann::json::exception& e) {
    throw sio::SerializationError(e.what());
  }
}

siomsg::JsonMessageType siomsg::JsonSerializer::deserialize(
    std::string const& blob) {
  try {
    return nlohmann::json::parse(blob);
  } catch (nlohmann::json::exception& e) {
    throw sio::SerializationError(e.what());
  }
}
