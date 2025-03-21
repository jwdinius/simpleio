#include <iostream>
#include <memory>

#include <Poco/DOM/AutoPtr.h>
#include <Poco/DOM/Document.h>
#include <Poco/DOM/DOMParser.h>
#include <gtest/gtest.h>

#include "simpleio/xml_message/xml_message.hpp"

// Example test case using the test harness
TEST(XmlMessageTest, TestPackUnpackNominal) {
    // Create an XML document
    Poco::AutoPtr<Poco::XML::Document> doc = new Poco::XML::Document;
    Poco::AutoPtr<Poco::XML::Element> event = doc->createElement("message");
    event->setAttribute("id", "1");
    event->setAttribute("contents", "Hello, world!");
    doc->appendChild(event);

    auto strategy = std::make_shared<simpleio::xml_message::XmlSerializer>();
    auto xml_msg = std::make_shared<simpleio::xml_message::XmlMessage>(std::move(doc), strategy);
    {
       auto entity = xml_msg->entity();
       EXPECT_NE(entity, nullptr);
       auto message = entity->documentElement();
       EXPECT_NE(message, nullptr);
       EXPECT_EQ(message->nodeName(), "message");
       EXPECT_EQ(message->getAttribute("id"), "1");
       EXPECT_EQ(message->getAttribute("contents"), "Hello, world!");
    }

    // Copy the packed entity
    std::vector<std::byte> serialized_xml_msg {xml_msg->blob().begin(), xml_msg->blob().end()};

    // Create a new XmlMessage from the packed entity
    auto xml_msg_from_serialized = std::make_shared<simpleio::xml_message::XmlMessage>(std::move(serialized_xml_msg), strategy);

    // Verify the unpacked XML document
    {
       auto entity = xml_msg_from_serialized->entity();
       auto message = entity->documentElement();
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