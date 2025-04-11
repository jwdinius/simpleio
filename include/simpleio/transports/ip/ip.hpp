// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip {

/// @brief Enumeration of transport schemes.
enum class Scheme { TCP, TLS, UDP, UDP_BROADCAST, UDP_WRITE_ONLY };

/// @brief IO worker.
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
  [[nodiscard]] std::shared_ptr<boost::asio::io_context> get_task_scheduler()
      const;

 private:
  std::shared_ptr<boost::asio::io_context> task_scheduler_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      lifecycle_manager_;
  std::thread worker_;
};

// NOLINTBEGIN [build/namespaces]
template <typename MessageT>
std::shared_ptr<Sender<MessageT>> make_sender(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    std::string const& remote_ip, uint16_t const& remote_port,
    TlsConfig const& tls_config = {}) {
  // NOLINTEND [build/namespaces]
  switch (scheme) {
    case Scheme::TCP: {
      auto sndr_strategy = std::make_shared<TcpSendStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(remote_ip), remote_port));
      return std::make_shared<Sender<MessageT>>(sndr_strategy);
    }
    case Scheme::TLS: {
      auto tls_sndr_strategy = std::make_shared<TlsSendStrategy>(
          io_wrkr->get_task_scheduler(), tls_config,
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(remote_ip), remote_port));
      return std::make_shared<Sender<MessageT>>(tls_sndr_strategy);
    }
    case Scheme::UDP: {
      auto socket = std::make_shared<boost::asio::ip::udp::socket>(
          *(io_wrkr->get_task_scheduler()));
      auto udp_sndr_strategy = std::make_shared<UdpSendStrategy>(
          socket,
          boost::asio::ip::udp::endpoint(
              boost::asio::ip::address::from_string(remote_ip), remote_port));
      return std::make_shared<Sender<MessageT>>(udp_sndr_strategy);
    }
    default:
      throw TransportException("Unsupported transport scheme: " +
                               std::to_string(static_cast<int>(scheme)));
  }
}

// NOLINTBEGIN [build/namespaces]
template <typename MessageT, typename SerializerT>
std::unique_ptr<Receiver<MessageT>> make_receiver(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    std::string const& local_ip, uint16_t const& local_port,
    std::function<void(MessageT const&)> message_cb,
    TlsConfig const& tls_config = {}) {
  // NOLINTEND [build/namespaces]
  auto serializer = std::make_shared<SerializerT>();
  switch (scheme) {
    case Scheme::TCP: {
      auto strategy = std::make_shared<TcpReceiveStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(local_ip), local_port),
          MessageT::max_blob_size);
      return std::make_unique<Receiver<MessageT>>(strategy, serializer,
                                                  message_cb);
    }
    case Scheme::TLS: {
      auto strategy = std::make_shared<TlsReceiveStrategy>(
          io_wrkr->get_task_scheduler(), tls_config,
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(local_ip), local_port),
          MessageT::max_blob_size);
      return std::make_unique<Receiver<MessageT>>(strategy, serializer,
                                                  message_cb);
    }
    case Scheme::UDP: {
      auto strategy = std::make_shared<UdpReceiveStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::udp::endpoint(
              boost::asio::ip::address::from_string(local_ip), local_port),
          MessageT::max_blob_size);
      return std::make_unique<Receiver<MessageT>>(strategy, serializer,
                                                  message_cb);
    }
    default:
      throw TransportException("Unsupported transport scheme: " +
                               std::to_string(static_cast<int>(scheme)));
  }
}

}  // namespace simpleio::transports::ip
