#pragma once

#include <memory>
#include <stdexcept>
#include <vector>

#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"

namespace simpleio {

class TransportException : public std::runtime_error
{
public:
    explicit TransportException(std::string const& what) : std::runtime_error(what) {}
};

/// @brief Strategy for sending messages.
/// @details Implementations of this class are responsible for sending messages
///          over a system interface (e.g., network, serial, etc.).
class SendStrategy
{
public:
    /// @brief Declare default destructor to allow inheritance.
    virtual ~SendStrategy() = default;

    /// @brief Send a byte vector.
    /// @param blob, the byte vector to send.
    /// @throw TransportException, if an error occurs during sending.
    virtual void send(std::vector<std::byte> const& blob) = 0;
};

/// @brief Message sender
/// @details This class is responsible for sending messages of type MessageT
///          using a SendStrategy object.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender
{
public:
    
    /// @brief Default constructor deleted.
    Sender() = delete;

    /// @brief Construct from a SendStrategy object.
    /// @param strategy, the SendStrategy object to use.
    explicit Sender(std::shared_ptr<SendStrategy> strategy)
    : strategy_(strategy)
    {
    }

    ~Sender() = default;

    /// @brief Send a message.
    /// @param message, the message to send.
    /// @throw TransportException, if an error occurs during sending. 
    void send(MessageT const& message)
    {
        std::vector<std::byte> blob {message.blob().begin(), message.blob().end()};
        strategy_->send(blob);
    }

private:
    std::shared_ptr<SendStrategy> strategy_;
};

/// @brief Strategy for receiving messages.
/// @details Implementations of this class are responsible for receiving messages
///          over a system interface (e.g., network, serial, etc.).
class ReceiveStrategy
{
public:
    
    /// @brief Default constructor deleted.
    ReceiveStrategy() = default;

    /// @brief Declare default destructor to allow inheritance.
    virtual ~ReceiveStrategy() = default;

    /// @brief Grant Receiver access to the blob queue to unpack messages.
    friend class Receiver;

protected:
    AsyncQueue<std::vector<std::byte>> blob_queue_;
};

/// @brief Message receiver
/// @details This class is responsible for receiving messages of type MessageT
///          using a ReceiveStrategy object.
class Receiver {
public:
    /// @brief Default constructor deleted.
    Receiver() = delete;

    /// @brief Construct from a ReceiveStrategy object.
    /// @param strategy, the ReceiveStrategy object to use.
    explicit Receiver(std::shared_ptr<ReceiveStrategy> strategy)
    : strategy_(strategy)
    {}
    
    /// @brief Extract a message from the receive queue.
    /// @return MessageT, the extracted message.
    template<typename MessageT>
    MessageT extract_message(
        std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>> serializer)
    {
        return MessageT(std::move(strategy_->blob_queue_.wait_and_pop()), serializer);
    }

private:
    std::shared_ptr<ReceiveStrategy> strategy_;
};
}  // namespace simpleio