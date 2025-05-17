// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include <Poco/DOM/AutoPtr.h>
#include <Poco/DOM/DOMParser.h>
#include <Poco/DOM/Document.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

#include "simpleio/messages/xml.hpp"

namespace sio = simpleio;
namespace siomsg = simpleio::messages;

// Example test case using the test harness
TEST(XmlMessageTest, TestPackUnpackNominal) {
  // Create an XML document
  Poco::AutoPtr<Poco::XML::Document> doc = new Poco::XML::Document;
  Poco::AutoPtr<Poco::XML::Element> event = doc->createElement("message");
  event->setAttribute("id", "1");
  event->setAttribute("contents", "Hello, world!");
  doc->appendChild(event);

  auto strategy = std::make_shared<siomsg::XmlSerializer>();
  auto xml_msg = std::make_shared<sio::Message<siomsg::XmlMessageType>>(
      std::move(doc), strategy);
  {
    auto entity = xml_msg->entity();
    EXPECT_NE(entity, nullptr);
    auto *message = entity->documentElement();
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->nodeName(), "message");
    EXPECT_EQ(message->getAttribute("id"), "1");
    EXPECT_EQ(message->getAttribute("contents"), "Hello, world!");
  }

  // Copy the packed entity
  std::string serialized_xml_msg{xml_msg->blob()};

  // Create a new XmlMessage from the packed entity
  auto xml_msg_from_serialized =
      std::make_shared<sio::Message<siomsg::XmlMessageType>>(
          std::move(serialized_xml_msg), strategy);

  // Verify the unpacked XML document
  {
    auto entity = xml_msg_from_serialized->entity();
    auto *message = entity->documentElement();
    EXPECT_NE(message, nullptr);
    EXPECT_EQ(message->nodeName(), "message");
    EXPECT_EQ(message->getAttribute("id"), "1");
    EXPECT_EQ(message->getAttribute("contents"), "Hello, world!");
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
