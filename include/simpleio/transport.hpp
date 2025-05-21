// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"
#include "simpleio/worker.hpp"

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

  /// @brief Send a string.
  /// @param blob, the string to send.
  /// @throw TransportException, if an error occurs during sending.
  virtual void send(std::string const& blob) = 0;
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
    strategy_->send(message.blob());
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
      std::function<void(std::string const&)> const& event_cb) {
    event_cb_ = event_cb;
  }

 protected:
  std::function<void(std::string const&)> event_cb_;
};

/// @brief Message receiver
/// @details This class is responsible for receiving messages of type MessageT
///          using a ReceiveStrategy object.
template <typename MessageT>
class Receiver {
 public:
  /// @brief Default constructor deleted.
  Receiver() = delete;

  /// @brief Constructor.
  /// @param strategy, the ReceiveStrategy object to use.
  /// @param serializer, the SerializationStrategy object to use.
  /// @param message_cb, the callback function to call when a message is
  ///                    received.
  explicit Receiver(
      std::shared_ptr<ReceiveStrategy> strategy,
      std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>>
          serializer,
      std::function<void(MessageT const&)> message_cb)
      : strategy_(std::move(strategy)),
        serializer_(std::move(serializer)),
        event_queue_(std::make_shared<AsyncQueue<MessageT>>()) {
    strategy_->set_event_callback([this](std::string const& blob) {
      auto message = MessageT(blob, serializer_);
      event_queue_->push(message);
    });
    worker_ = std::make_unique<Worker<MessageT>>(event_queue_, message_cb);
  }

  /// @brief Destructor for the Receiver class.
  /// @details This destructor shuts down the worker thread and cleans up
  ///          resources.
  ~Receiver() {
    worker_->shutdown();
  }

 protected:
  std::shared_ptr<ReceiveStrategy> strategy_;
  std::shared_ptr<SerializationStrategy<typename MessageT::entity_type>>
      serializer_;
  std::shared_ptr<AsyncQueue<MessageT>> event_queue_;
  std::unique_ptr<Worker<MessageT>> worker_;
};

template <typename ServiceT>
class Client : public Sender<typename ServiceT::RequestT>,
               public Receiver<typename ServiceT::ResponseT> {
 public:
  /// @brief Default constructor deleted.
  Client() = delete;

  /// @brief Constructor.
  explicit Client(
      std::shared_ptr<SendStrategy> request_strategy,
      std::shared_ptr<ReceiveStrategy> response_strategy,
      std::shared_ptr<
          SerializationStrategy<typename ServiceT::ResponseT::entity_type>>
          response_serializer,
      std::function<void(typename ServiceT::ResponseT const&)> response_cb)
      : Sender<typename ServiceT::RequestT>(std::move(request_strategy)),
        Receiver<typename ServiceT::ResponseT>(std::move(response_strategy),
                                               std::move(response_serializer),
                                               std::move(response_cb)) {}
};

template <typename ServiceT>
class Server : public Sender<typename ServiceT::ResponseT>,
               public Receiver<typename ServiceT::RequestT> {
 public:
  /// @brief Default constructor deleted.
  Server() = delete;

  /// @brief Constructor.
  explicit Server(
      std::shared_ptr<SendStrategy> response_strategy,
      std::shared_ptr<ReceiveStrategy> request_strategy,
      std::shared_ptr<
          SerializationStrategy<typename ServiceT::RequestT::entity_type>>
          request_serializer,
      std::function<void(typename ServiceT::RequestT const&)> request_cb)
      : Sender<typename ServiceT::ResponseT>(std::move(response_strategy)),
        Receiver<typename ServiceT::RequestT>(std::move(request_strategy),
                                              std::move(request_serializer),
                                              std::move(request_cb)) {}
};
}  // namespace simpleio
