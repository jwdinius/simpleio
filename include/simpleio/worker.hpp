// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <atomic>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "simpleio/async_queue.hpp"

namespace simpleio {
class Worker {
 public:
  Worker() : threads_{1} {
    run();
  }

  explicit Worker(size_t num_threads) : threads_(num_threads) {
    run();
  }

  /// @brief Destructor for the Worker class.
  /// @details This destructor shuts down the worker thread and cleans up
  ///          resources.
  ~Worker() {
    shutdown();
  }

  /// @brief Shut down and join the worker thread.
  void shutdown() {
    shutdown_ = true;
    tasks_.shutdown();
    for (auto&& thread : threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }

  /// @brief Push a task to the worker thread.
  template <typename F, typename... Args>
  std::future<typename std::result_of<F(Args...)>::type> push(F&& f,
                                                              Args&&... args) {
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    tasks_.push([task]() { (*task)(); });
    return res;
  }

 private:
  /// @brief Run the worker.
  /// @details This function runs the worker, waiting for messages to
  void run() {
    for (auto&& thread : threads_) {
      thread = std::thread([this] {
        while (!shutdown_) {
          while (tasks_.try_pop() == std::nullopt) {
            std::this_thread::yield();
          }
          auto task = std::move(tasks_.pop());
          task();
        }
      });
    }
  }

  std::atomic<bool> shutdown_{false};
  std::vector<std::thread> threads_;
  AsyncQueue<std::function<void()>> tasks_;
};

}  // namespace simpleio
