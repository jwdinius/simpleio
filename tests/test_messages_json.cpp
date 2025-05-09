// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <memory>
#include <nlohmann/json.hpp>
#include <utility>
#include <vector>

#include "simpleio/messages/json.hpp"

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

// Example test case using the test harness
TEST(JsonMessageTest, TestPackUnpackNominal) {
  // Create a JSON object
  nlohmann::json json_obj;
  json_obj["id"] = 1;
  json_obj["contents"] = "Hello, world!";

  auto strategy = std::make_shared<siomsg::JsonSerializer>();
  auto json_msg = std::make_shared<sio::Message<siomsg::JsonMessageType>>(
      json_obj, strategy);
  {
    auto entity = json_msg->entity();
    EXPECT_NE(entity, nullptr);
  }

  // Copy the packed entity
  std::vector<std::byte> serialized_json_msg{json_msg->blob().begin(),
                                             json_msg->blob().end()};

  // Create a new JsonMessage from the packed entity
  auto json_msg_from_serialized =
      std::make_shared<sio::Message<siomsg::JsonMessageType>>(
          std::move(serialized_json_msg), strategy);

  // Verify the unpacked JSON object
  {
    auto entity = json_msg_from_serialized->entity();
    EXPECT_NE(entity, nullptr);
    EXPECT_EQ(entity["id"], 1);
    EXPECT_EQ(entity["contents"], "Hello, world!");
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
