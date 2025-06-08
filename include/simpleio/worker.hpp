// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <atomic>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include "simpleio/async_queue.hpp"

namespace simpleio {
/// @brief Worker class for managing a pool of threads to execute tasks
/// asynchronously.
class Worker {
 public:
  /// @brief Default constructor for the Worker class.
  /// @details This constructor initializes the worker with a single thread and
  ///          starts running it.
  Worker() : threads_{1} {
    run();
  }

  /// @brief Constructor for the Worker class with a specified number of
  /// threads.
  /// @param num_threads, the number of threads to create for the worker.
  /// @throw std::invalid_argument, if num_threads is zero.
  explicit Worker(size_t num_threads) : threads_(num_threads) {
    if (num_threads == 0) {
      throw std::invalid_argument(
          "Number of threads must be greater than zero.");
    }
    run();
  }

  /// @brief Destructor for the Worker class.
  /// @details This destructor shuts down the worker thread and cleans up
  ///          resources.
  ~Worker() {
    shutdown();
  }

  /// @brief Shut down and join the worker threads.
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
  /// @tparam F, the type of the function to execute.
  /// @tparam Args, the types of the arguments to pass to the function.
  /// @param func, the function to execute.
  /// @param args, the arguments to pass to the function.
  /// @return a future that will hold the result of the
  ///         function execution.
  template <typename F, typename... Args>
  std::future<std::invoke_result_t<F, Args...>> push(F&& func, Args&&... args) {
    using return_type = std::invoke_result_t<F, Args...>;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(func), std::forward<Args>(args)...));

    std::future<return_type> res = task->get_future();
    tasks_.push([task]() { (*task)(); });
    return res;
  }

 private:
  /// @brief Run the worker.
  /// @details Each thread will wait for tasks to be pushed onto the queue and
  ///          execute them until the worker is shut down.
  void run() {
    for (auto&& thread : threads_) {
      thread = std::thread([this] {
        while (true) {
          auto task = tasks_.wait_and_pop();
          if (!task || shutdown_) {
            break;
          }
          (*task)();
        }
      });
    }
  }

  std::atomic<bool> shutdown_{false};
  std::vector<std::thread> threads_;
  AsyncQueue<std::function<void()>> tasks_;
};

}  // namespace simpleio
