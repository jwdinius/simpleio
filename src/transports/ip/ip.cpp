// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/ip/ip.hpp"

#include <memory>
#include <utility>

using namespace simpleio::transports::ip;  // NOLINT [build/namespaces]
namespace basio = boost::asio;

IoWorker::IoWorker()
    : scheduler_(std::make_shared<basio::io_context>()),
      executor_(std::make_shared<simpleio::Worker>(1)) {
  BOOST_LOG_TRIVIAL(debug) << "Created IoWorker with shared io_context";
  BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
  // Prevent io_context from exiting when idle
  lifecycle_manager_ = std::make_unique<
      basio::executor_work_guard<boost::asio::io_context::executor_type>>(
      scheduler_->get_executor());

  scheduler_thread_ = std::thread([this] {
    BOOST_LOG_TRIVIAL(debug) << "io_context running...";
    scheduler_->run();
    BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
  });
}

IoWorker::~IoWorker() {
  BOOST_LOG_TRIVIAL(debug) << "Stopping io_context thread";
  lifecycle_manager_.reset();
  scheduler_->stop();
  executor_->shutdown();
  if (scheduler_thread_.joinable()) {
    scheduler_thread_.join();
  }
  BOOST_LOG_TRIVIAL(debug) << "Stopped io_context thread";
}

std::shared_ptr<boost::asio::io_context> IoWorker::scheduler() const {
  return scheduler_;
}

std::shared_ptr<simpleio::Worker> IoWorker::executor() const {
  return executor_;
}
