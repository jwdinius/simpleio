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
#include <vector>

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/http.hpp"
#include "simpleio/transports/ip/https.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip {

static constexpr size_t UDP_BLOB_SIZE{1400};
static constexpr size_t TCP_BLOB_SIZE{64000};

template <typename EntityT>
using TcpSerializer = Serializer<EntityT, TCP_BLOB_SIZE>;

template <typename EntityT>
using UdpSerializer = Serializer<EntityT, UDP_BLOB_SIZE>;

template <typename EntityT>
using TcpMessage = Message<TcpSerializer<EntityT>>;

template <typename EntityT>
using UdpMessage = Message<UdpSerializer<EntityT>>;

/// @brief IO worker.
/// @details An IoWorker sets up a shared task scheduler, lifecycle manager,
///          and callback executor for sending and receiving messages over
///          network interfaces within a single process.
class IoWorker {
 public:
  /// @brief Default constructor
  /// @details Creates an io context running on a single thread
  IoWorker();

  /// @brief Constructor specifying number of threads for io context
  explicit IoWorker(uint8_t num_threads);

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
  std::vector<std::thread> scheduler_threads_;
};
}  // namespace simpleio::transports::ip
