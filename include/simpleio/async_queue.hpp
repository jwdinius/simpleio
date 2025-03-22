// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>

namespace simpleio {

/// @brief A thread-safe queue for storing messages of type T.
/// @details This class provides a thread-safe queue for storing messages of
/// type T.
///          It is intended for use in asynchronous I/O operations where
///          messages are received and processed in separate threads.
/// @tparam T, the type of message to store in the queue.
template <typename T>
class AsyncQueue {
 public:
  /// @brief Push a message onto the queue.
  /// @param value, the message to push onto the queue.
  void push(T value) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(value));
    cv_.notify_one();
  }

  /// @brief Attempt to pop a message from the queue.
  /// @return std::optional<T>, the popped message if the queue is not empty.
  std::optional<T> try_pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) return std::nullopt;
    auto value = std::move(queue_.front());
    queue_.pop();
    return value;
  }

  /// @brief Wait for and pop a message from the queue.
  /// @return T, the popped message.
  T wait_and_pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !queue_.empty(); });
    T value = std::move(queue_.front());
    queue_.pop();
    return value;
  }

 private:
  std::queue<T> queue_;
  std::mutex mutex_;
  std::condition_variable cv_;
};
}  // namespace simpleio
