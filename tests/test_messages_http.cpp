// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <boost/beast/http.hpp>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/messages/http.hpp"

namespace sio = simpleio;
namespace siomsg = simpleio::messages;
using Request = siomsg::HttpRequestType<boost::beast::http::string_body>;

// Example test case using the test harness
TEST(HttpTest, TestRequestPackUnpackNominal) {
  // Create a request object
  Request request;
  request.method(boost::beast::http::verb::post);
  request.target("/test");
  request.version(11);
  request.set(boost::beast::http::field::host, "localhost");
  request.set(boost::beast::http::field::user_agent, "TestAgent");
  request.set(boost::beast::http::field::content_type, "text/plain");
  request.body() = "Hello, World!";
  request.prepare_payload();  // sets Content-Length

  // Serialize the request
  siomsg::HttpRequestSerializer<boost::beast::http::string_body> serializer;
  std::string serialized_request = serializer.serialize(request);

  // Deserialize the request
  Request deserialized_request = serializer.deserialize(serialized_request);

  // Check that the deserialized request matches the original
  EXPECT_EQ(request.method(), deserialized_request.method());
  EXPECT_EQ(request.target(), deserialized_request.target());
  EXPECT_EQ(request.version(), deserialized_request.version());
  EXPECT_EQ(request.body(), deserialized_request.body());
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
