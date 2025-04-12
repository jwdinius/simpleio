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

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip {

/// @brief Enumeration of transport schemes.
enum class Scheme {
  TCP,
  TLS,
  UDP,
  UDP_BROADCAST,
  UDP_MULTICAST,
  UDP_WRITE_ONLY
};

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

struct SenderOptions {
  std::string remote_ip;
  uint16_t remote_port;
  std::optional<TlsConfig> tls_config;
};

// NOLINTBEGIN [build/namespaces]
template <typename MessageT>
std::shared_ptr<Sender<MessageT>> make_sender(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    SenderOptions const& options) {
  // NOLINTEND [build/namespaces]
  switch (scheme) {
    case Scheme::TCP: {
      auto sndr_strategy = std::make_shared<TcpSendStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.remote_ip),
              options.remote_port));
      return std::make_shared<Sender<MessageT>>(sndr_strategy);
    }
    case Scheme::TLS: {
      if (!options.tls_config) {
        throw TransportException("TLS config is required for TLS scheme");
      }
      auto tls_sndr_strategy = std::make_shared<TlsSendStrategy>(
          io_wrkr->get_task_scheduler(), options.tls_config.value(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.remote_ip),
              options.remote_port));
      return std::make_shared<Sender<MessageT>>(tls_sndr_strategy);
    }
    case Scheme::UDP: {
      auto socket = std::make_shared<boost::asio::ip::udp::socket>(
          *(io_wrkr->get_task_scheduler()));
      auto udp_sndr_strategy = std::make_shared<UdpSendStrategy>(
          socket, boost::asio::ip::udp::endpoint(
                      boost::asio::ip::address::from_string(options.remote_ip),
                      options.remote_port));
      return std::make_shared<Sender<MessageT>>(udp_sndr_strategy);
    }
    default:
      throw TransportException("Unsupported transport scheme: " +
                               std::to_string(static_cast<int>(scheme)));
  }
}

struct ReceiverOptions {
  std::string local_ip;
  uint16_t local_port;
  std::optional<TlsConfig> tls_config;
};

// NOLINTBEGIN [build/namespaces]
template <typename MessageT>
std::unique_ptr<Receiver<MessageT>> make_receiver(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    std::shared_ptr<
        SerializationStrategy<typename MessageT::entity_type>> const&
        serializer,
    std::function<void(MessageT const&)> message_cb,
    ReceiverOptions const& options) {
  // NOLINTEND [build/namespaces]
  switch (scheme) {
    case Scheme::TCP: {
      auto strategy = std::make_shared<TcpReceiveStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip),
              options.local_port),
          MessageT::max_blob_size);
      return std::make_unique<Receiver<MessageT>>(strategy, serializer,
                                                  message_cb);
    }
    case Scheme::TLS: {
      if (!options.tls_config) {
        throw TransportException("TLS config is required for TLS scheme");
      }
      auto strategy = std::make_shared<TlsReceiveStrategy>(
          io_wrkr->get_task_scheduler(), options.tls_config.value(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip),
              options.local_port),
          MessageT::max_blob_size);
      return std::make_unique<Receiver<MessageT>>(strategy, serializer,
                                                  message_cb);
    }
    case Scheme::UDP: {
      auto strategy = std::make_shared<UdpReceiveStrategy>(
          io_wrkr->get_task_scheduler(),
          boost::asio::ip::udp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip),
              options.local_port),
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
