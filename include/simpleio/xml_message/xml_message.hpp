#pragma once
#include <memory>
#include <span>

#include <Poco/DOM/Document.h>
#include <Poco/DOM/AutoPtr.h>

#include "simpleio/message.hpp"

namespace simpleio {
namespace xml_message {

using MessageType = Poco::XML::AutoPtr<Poco::XML::Document>;
static constexpr size_t MaxBlobSize = 1024;

class XmlSerializer : public SerializationStrategy<MessageType> {
public:

    std::vector<std::byte> serialize(MessageType const& entity) override;
    MessageType deserialize(std::vector<std::byte> const& entity) override;
};

class XmlMessage : public Message<MessageType, MaxBlobSize> {
public:
    
    explicit XmlMessage(MessageType&& entity, std::shared_ptr<XmlSerializer> strategy);

    explicit XmlMessage(std::vector<std::byte>&& blob, std::shared_ptr<XmlSerializer> strategy);
};

} // namespace xml_message
} // namespace simpleio