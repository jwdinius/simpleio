#pragma once

#include <memory>
    
#include "simpleio/message.hpp"

namespace simpleio {

class SendStrategy {
public:
    virtual void send(std::vector<std::byte> const& blob) = 0;
};

template <typename MessageT>
class Sender {
public:
    Sender() = delete;
    explicit Sender(std::shared_ptr<SendStrategy> strategy)
    : strategy_(strategy)
    {}

    ~Sender() = default;

    void send(MessageT const& message) {
        std::vector<std::byte> blob {message.blob().begin(), message.blob().end()};
        strategy_->send(blob);
    }
private:
    std::shared_ptr<SendStrategy> strategy_;
};

template <typename MessageT>
class ReceiveStrategy {
public:
    explicit ReceiveStrategy(std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>> serializer)
    : serializer_(serializer)
    {}

    virtual ~ReceiveStrategy() = default;

    virtual MessageT pop_message() = 0;

    std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>> serializer() const {
        return serializer_;
    }
protected:
    std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>> const serializer_;
};

template <typename MessageT>
class Receiver {
public:
    Receiver() = delete;
    explicit Receiver(std::shared_ptr<ReceiveStrategy<MessageT>> strategy)
    : strategy_(strategy)
    {}

    MessageT pop_message() {
        return strategy_->pop_message();
    }

    ~Receiver() = default;

private:
    std::shared_ptr<ReceiveStrategy<MessageT>> strategy_;
};
}  // namespace simpleio