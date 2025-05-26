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
/// @brief Exception thrown when a transport error occurs at runtime.
class TransportException : public std::runtime_error {
 public:
  explicit TransportException(std::string const& what)
      : std::runtime_error(what) {}
};

/// @brief Message sender
/// @details This class is responsible for sending messages of type MessageT
///          using a SendStrategy object.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender {
 public:
  using message_t = MessageT;

  /// @brief Default destructor.
  virtual ~Sender() = default;

  /// @brief Send a message.
  /// @param message, the message to send.
  /// @throw TransportException, if an error occurs during sending.
  virtual void send(MessageT const& msg) = 0;
};

/// @brief Message receiver
/// @details This class is responsible for receiving messages of type MessageT
///          using a ReceiveStrategy object.
template <typename MessageT, typename F = std::function<void(MessageT const&)>>
class Receiver {
 public:
  using message_t = MessageT;
  using callback_t = F;
  using callback_return_t =
      typename std::result_of<callback_t(message_t const&)>::type;

  /// @brief Default constructor deleted.
  Receiver() = delete;

  /// @brief Constructor.
  /// @param message_cb, the callback function to call when a message is
  ///                    received.
  /// @param worker, the worker to use for processing messages.
  explicit Receiver(callback_t message_cb, std::shared_ptr<Worker> worker)
      : message_cb_(std::move(message_cb)), worker_(std::move(worker)) {
    if (!message_cb_) {
      throw TransportException("Message callback cannot be null.");
    }
    if (!worker_) {
      throw TransportException("Worker cannot be null.");
    }
  }

  /// @brief Destructor for the Receiver class.
  virtual ~Receiver() = default;

 protected:
  void on_read(MessageT const& message) {
    callback_futures_.push(worker_->push(
        [this](message_t const& msg) -> callback_return_t {
          return message_cb_(msg);
        },
        message));
  }

 private:
  callback_t message_cb_;
  std::shared_ptr<Worker> worker_;
  AsyncQueue<std::future<callback_return_t>> callback_futures_;
};
}  // namespace simpleio
