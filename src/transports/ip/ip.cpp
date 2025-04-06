// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/ip/ip.hpp"

#include <memory>
#include <utility>

using namespace simpleio::transports::ip;  // NOLINT [build/namespaces]

IoWorker::IoWorker()
    : task_scheduler_(std::make_shared<detail::TaskSchedulerImpl>()) {
  BOOST_LOG_TRIVIAL(debug) << "Created IoWorker with shared io_context";
  BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
  // Prevent io_context from exiting when idle
  lifecycle_manager_ = std::make_unique<detail::LifecycleManagerImpl>(
      task_scheduler_->get_executor());

  worker_ = std::thread([this] {
    BOOST_LOG_TRIVIAL(debug) << "io_context running...";
    task_scheduler_->run();
    BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
  });
}

IoWorker::~IoWorker() {
  BOOST_LOG_TRIVIAL(debug) << "Stopping io_context thread";
  lifecycle_manager_.reset();
  task_scheduler_->stop();
  if (worker_.joinable()) {
    worker_.join();
  }
  BOOST_LOG_TRIVIAL(debug) << "Stopped io_context thread";
}

std::shared_ptr<detail::TaskSchedulerImpl> IoWorker::get_task_scheduler()
    const {
  return task_scheduler_;
}
