// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ThreadPool.h"
#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"

namespace simpleio {

class TransportException : public std::runtime_error {
 public:
  explicit TransportException(std::string const& what)
      : std::runtime_error(what) {}
};

/// @brief Strategy for sending messages.
/// @details Implementations of this class are responsible for sending messages
///          over a system interface (e.g., network, serial, etc.).
class SendStrategy {
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
class Sender {
 public:
  /// @brief Default constructor deleted.
  Sender() = delete;

  /// @brief Construct from a SendStrategy object.
  /// @param strategy, the SendStrategy object to use.
  explicit Sender(std::shared_ptr<SendStrategy> strategy)
      : strategy_(std::move(strategy)) {}

  ~Sender() = default;

  /// @brief Send a message.
  /// @param message, the message to send.
  /// @throw TransportException, if an error occurs during sending.
  void send(MessageT const& message) {
    std::vector<std::byte> blob{message.blob().begin(), message.blob().end()};
    strategy_->send(blob);
  }

 private:
  std::shared_ptr<SendStrategy> strategy_;
};

/// @brief Strategy for receiving messages.
/// @details Implementations of this class are responsible for receiving
/// messages
///          over a system interface (e.g., network, serial, etc.).
class ReceiveStrategy {
 public:
  ReceiveStrategy() = default;

  /// @brief Declare default destructor to allow inheritance.
  virtual ~ReceiveStrategy() = default;

  void set_event_callback(
      std::function<void(std::vector<std::byte> const&)> const& event_cb) {
    event_cb_ = event_cb;
  }

  /// @brief Grant Receiver access to the blob queue to unpack messages.
  // friend class Receiver;

 protected:
  std::function<void(std::vector<std::byte> const&)> event_cb_;

  // AsyncQueue<std::vector<std::byte>> ;
};

/// @brief Message receiver
/// @details This class is responsible for receiving messages of type MessageT
///          using a ReceiveStrategy object.
template <typename MessageT>
class Receiver {
 public:
  /// @brief Default constructor deleted.
  Receiver() = delete;

  /// @brief Construct from a ReceiveStrategy object.
  /// @param strategy, the ReceiveStrategy object to use.
  explicit Receiver(
      std::shared_ptr<ReceiveStrategy> strategy,
      std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>>
          serializer,
      std::shared_ptr<ThreadPool> event_handler,
      std::function<void(MessageT const&)> const& message_cb)
      : strategy_(std::move(strategy)),
        serializer_(std::move(serializer)),
        event_handler_(std::move(event_handler)) {
    strategy_->set_event_callback(
        [this, message_cb](std::vector<std::byte> const& blob) {
          auto message = MessageT(blob, serializer_);
          futures_.push(event_handler_->enqueue(
              [message, message_cb] { return message_cb(message); }));
        });
  }

  void wait_for(std::chrono::milliseconds const& period) {
    std::this_thread::sleep_for(period);
    if (!futures_.empty()) {
      auto& future = futures_.front();
      if (future.valid()) {
        future.get();
      }
      futures_.pop();
    }
  }

 private:
  std::shared_ptr<ReceiveStrategy> strategy_;
  std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>>
      serializer_;
  std::shared_ptr<ThreadPool> event_handler_;
  std::queue<std::future<void>> futures_;
};
}  // namespace simpleio
