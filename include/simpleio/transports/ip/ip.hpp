// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/log/trivial.hpp>
#include <memory>
#include <thread>

#include "simpleio/transports/ip/detail/ip_impl.hpp"

namespace simpleio::transports::ip {
/// @brief Enumeration of transport schemes.
enum class Scheme { TLS, TCP, UDP, UDP_BROADCAST, UDP_WRITE_ONLY };

/// @brief IO worker.
class IoWorker {
 public:
  /// @brief Constructor.
  IoWorker();

  /// @brief Destructor.
  ~IoWorker();

  friend class UdpSendStrategy;
  friend class UdpReceiveStrategy;
  friend class TcpSendStrategy;
  friend class TcpReceiveStrategy;
  friend class TlsSendStrategy;
  friend class TlsReceiveStrategy;

  // protected:  // TODO: Make this protected again
  /// @brief Get the shared task scheduler.
  /// @details Senders and Receivers within the same process should share the
  /// same
  ///          task scheduler to ensure that the same thread is used for sharing
  ///          data with other processes over a network interface.
  /// @return The shared task scheduler.
  std::shared_ptr<detail::TaskSchedulerImpl> get_task_scheduler() const;

 private:
  std::shared_ptr<detail::TaskSchedulerImpl> task_scheduler_;
  std::unique_ptr<detail::LifecycleManagerImpl> lifecycle_manager_;
  std::thread worker_;
};
}  // namespace simpleio::transports::ip
