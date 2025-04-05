// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <atomic>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include "simpleio/async_queue.hpp"

namespace simpleio {
/// @brief Worker class for processing messages from an AsyncQueue.
/// @details This class provides a worker thread that processes messages from
///          an AsyncQueue. The worker thread runs a loop that waits for
///          messages to arrive in the queue and then calls a user-defined
///          callback function to process the message.
/// @tparam MessageT, the type of message to process.
template <typename MessageT>
class Worker {
 public:
  /// @brief Delete the default constructor for the Worker class.
  Worker() = delete;

  /// @brief Construct a Worker object with a message queue and a callback.
  /// @param message_queue, the shared message queue to process messages from.
  /// @param message_cb, the callback function to call when a message is
  ///        received.
  explicit Worker(std::shared_ptr<AsyncQueue<MessageT>> message_queue,
                  std::function<void(MessageT const&)> message_cb)
      : message_queue_(std::move(message_queue)),
        message_cb_(std::move(message_cb)) {
    // Start the worker thread
    worker_thread_ = std::thread([this] {
      try {
        run();
      } catch (std::exception const& e) {
        std::cerr << "Worker thread exception: " << e.what() << std::endl;
      }
    });
  }

  /// @brief Destructor for the Worker class.
  /// @details This destructor shuts down the worker thread and cleans up
  ///          resources.
  virtual ~Worker() {
    shutdown();
  }

  /// @brief Shut down and join the worker thread.
  void shutdown() {
    shutdown_ = true;
    message_queue_->shutdown();
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

 private:
  /// @brief Run the worker thread.
  /// @details This function runs the worker thread, waiting for messages to
  ///          arrive in the queue and calling the user-defined callback.
  /// @throw std::runtime_error, if an error occurs during processing.
  void run() {
    while (!shutdown_) {
      auto message = message_queue_->wait_and_pop();
      if (message.has_value()) {
        message_cb_(message.value());
      }
    }
  }

  std::atomic<bool> shutdown_{false};
  std::shared_ptr<AsyncQueue<MessageT>> message_queue_;
  std::function<void(MessageT const&)> message_cb_;
  std::thread worker_thread_;
};

}  // namespace simpleio
