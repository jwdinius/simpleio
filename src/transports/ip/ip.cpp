// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/ip/detail/ip.hpp"

#include <memory>
#include <utility>

#include "simpleio/transports/ip/ip.hpp"

using namespace simpleio::transports::ip;  // NOLINT [build/namespaces]
namespace basio = boost::asio;

detail::Context::Context()
    : scheduler_(std::make_shared<basio::io_context>()), scheduler_threads_(1) {
  BOOST_LOG_TRIVIAL(debug) << "Created IoWorker with shared io_context";
  BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
  // Prevent io_context from exiting when idle.
  lifecycle_manager_ = std::make_unique<
      basio::executor_work_guard<boost::asio::io_context::executor_type>>(
      scheduler_->get_executor());

  scheduler_threads_[0] = std::thread([this] {
    BOOST_LOG_TRIVIAL(debug) << "io_context running...";
    scheduler_->run();
    BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
  });
}

detail::Context::Context(uint8_t num_threads)
    : scheduler_(std::make_shared<basio::io_context>()),
      scheduler_threads_(num_threads) {
  BOOST_LOG_TRIVIAL(debug) << "Created IoWorker with shared io_context and "
                           << std::to_string(num_threads) << " threads.";
  BOOST_LOG_TRIVIAL(debug) << "Starting io_context threads";
  // Prevent io_context from exiting when idle.
  lifecycle_manager_ = std::make_unique<
      basio::executor_work_guard<boost::asio::io_context::executor_type>>(
      scheduler_->get_executor());

  for (auto i = 0; i < scheduler_threads_.size(); ++i) {
    scheduler_threads_[i] = std::thread([this, i] {
      BOOST_LOG_TRIVIAL(debug) << "io_context running on thread " << i << "...";
      scheduler_->run();
      BOOST_LOG_TRIVIAL(debug) << "io_context stopped on thread " << i << "...";
    });
  }
}

detail::Context::~Context() {
  BOOST_LOG_TRIVIAL(debug) << "Stopping io_context threads";
  lifecycle_manager_.reset();
  scheduler_->stop();
  for (auto&& thread : scheduler_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  BOOST_LOG_TRIVIAL(debug) << "Stopped io_context threads";
}

Context::Context() : impl_(std::make_unique<detail::Context>()) {}

Context::Context(uint8_t num_threads)
    : impl_(std::make_unique<detail::Context>(num_threads)) {}

/// @brief Destructor.
Context::~Context() {
  impl_.reset();
}
