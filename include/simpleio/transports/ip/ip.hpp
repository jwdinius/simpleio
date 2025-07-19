// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/http.hpp"
#include "simpleio/transports/ip/https.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip {

/// @brief Enumeration of transport schemes.
enum class Scheme { HTTP, HTTPS, TCP, TLS, UDP, UDP_BROADCAST, UDP_MULTICAST };

/// @brief IO worker.
/// @details An IoWorker sets up a shared task scheduler, lifecycle manager,
///          and callback executor for sending and receiving messages over
///          network interfaces within a single process.
class IoWorker {
 public:
  /// @brief Constructor.
  IoWorker();

  /// @brief Destructor.
  ~IoWorker();

  /// @brief Get the shared task scheduler.
  /// @details Senders and Receivers within the same process should share the
  ///          same task scheduler to ensure that the same thread is used for
  ///          sharing data with other processes over a network interface.
  /// @return The shared task scheduler.
  [[nodiscard]] std::shared_ptr<boost::asio::io_context> scheduler() const;

 private:
  std::shared_ptr<boost::asio::io_context> scheduler_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      lifecycle_manager_;
  std::thread scheduler_thread_;
};
}  // namespace simpleio::transports::ip
