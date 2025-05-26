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
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/udp.hpp"
#include "simpleio/worker.hpp"

namespace simpleio::transports::ip {

/// @brief Enumeration of transport schemes.
enum class Scheme { TCP, TLS, UDP, UDP_BROADCAST, UDP_MULTICAST };

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
  [[nodiscard]] std::shared_ptr<boost::asio::io_context> scheduler() const;

  [[nodiscard]] std::shared_ptr<simpleio::Worker> executor() const;

 private:
  std::shared_ptr<boost::asio::io_context> scheduler_;
  std::shared_ptr<simpleio::Worker> executor_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      lifecycle_manager_;
  std::thread scheduler_thread_;
};

struct SenderOptions {
  std::string remote_ip;
  uint16_t remote_port;
  std::optional<TlsConfig> tls_config;
  std::optional<uint8_t> hops;   // for UDP_MULTICAST, == 0 for default
  std::optional<bool> loopback;  // for UDP_MULTICAST, == true for loopback
  std::optional<uint8_t> ipv6_interface;  // for UDP_MULTICAST, e.g., eth0 = 2
};

// NOLINTBEGIN [build/namespaces]
template <typename MessageT>
std::shared_ptr<Sender<MessageT>> make_sender(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    SenderOptions const& options) {
  // NOLINTEND [build/namespaces]
  auto io_ctx = io_wrkr->scheduler();
  switch (scheme) {
    case Scheme::TCP: {
      return std::make_shared<TcpSender<MessageT>>(
          io_ctx, boost::asio::ip::tcp::endpoint(
                      boost::asio::ip::address::from_string(options.remote_ip),
                      options.remote_port));
    }
    case Scheme::TLS: {
      if (!options.tls_config) {
        throw TransportException("TLS config is required for TLS scheme");
      }
      return std::make_shared<TlsSender<MessageT>>(
          io_ctx, options.tls_config.value(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.remote_ip),
              options.remote_port));
    }
    case Scheme::UDP: {
      auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);
      return std::make_shared<UdpSender<MessageT>>(
          socket, boost::asio::ip::udp::endpoint(
                      boost::asio::ip::address::from_string(options.remote_ip),
                      options.remote_port));
    }
    case Scheme::UDP_BROADCAST: {
      auto addr = boost::asio::ip::make_address(options.remote_ip);
      if (addr.is_v6()) {
        throw TransportException(
            "Broadcast scheme does not support IPv6 addresses");
      }
      auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);
      socket->open(boost::asio::ip::udp::v4());

      socket->set_option(boost::asio::socket_base::broadcast(true));
      auto endpoint =
          boost::asio::ip::udp::endpoint(addr.to_v4(), options.remote_port);

      return std::make_shared<UdpSender<MessageT>>(socket, endpoint);
    }
    case Scheme::UDP_MULTICAST: {
      auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);

      auto multicast_addr = boost::asio::ip::make_address(options.remote_ip);
      auto endpoint =
          boost::asio::ip::udp::endpoint(multicast_addr, options.remote_port);

      if (!multicast_addr.is_multicast()) {
        throw TransportException(
            "Provided address is not a valid multicast address");
      }
      if (!options.hops.has_value()) {
        throw TransportException(
            "Multicast hops value is required for multicast scheme");
      }
      if (!options.loopback.has_value()) {
        throw TransportException(
            "Multicast loopback value is required for multicast scheme");
      }

      if (multicast_addr.is_v4()) {
        socket->open(boost::asio::ip::udp::v4());

      } else if (multicast_addr.is_v6()) {
        socket->open(boost::asio::ip::udp::v6());

        // Specify the interface index (e.g., eth0 = 2)
        // 0 means "let OS choose default"
        socket->set_option(boost::asio::ip::multicast::join_group(
            multicast_addr.to_v6(), options.ipv6_interface.value_or(0)));
      } else {
        throw TransportException("Invalid multicast address: must be v4 or v6");
      }

      socket->set_option(
          boost::asio::ip::multicast::hops(options.hops.value()));
      socket->set_option(boost::asio::ip::multicast::enable_loopback(
          options.loopback.value()));

      return std::make_shared<UdpSender<MessageT>>(socket, endpoint);
    }
    default:
      throw TransportException("Control fell through for make_sender" +
                               std::to_string(static_cast<int>(scheme)));
  }
}

struct ReceiverOptions {
  std::optional<std::string> local_ip;
  uint16_t local_port;
  std::optional<TlsConfig> tls_config;
  std::optional<uint8_t> ipv6_interface;  // for UDP_MULTICAST, e.g., eth0 = 2
};

// NOLINTBEGIN [build/namespaces]
template <typename MessageT, typename F = std::function<void(MessageT const&)>>
std::shared_ptr<Receiver<MessageT>> make_receiver(
    std::shared_ptr<IoWorker> const& io_wrkr, Scheme const& scheme,
    F message_cb, ReceiverOptions const& options) {
  // NOLINTEND [build/namespaces]
  auto io_ctx = io_wrkr->scheduler();
  auto callback_handler = io_wrkr->executor();
  switch (scheme) {
    case Scheme::TCP: {
      if (!options.local_ip) {
        throw TransportException("Local IP is required for TCP scheme");
      }
      return std::make_shared<TcpReceiver<MessageT>>(
          io_ctx,
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip.value()),
              options.local_port),
          message_cb, callback_handler);
    }
    case Scheme::TLS: {
      if (!options.local_ip) {
        throw TransportException("Local IP is required for TLS scheme");
      }
      if (!options.tls_config) {
        throw TransportException("TLS config is required for TLS scheme");
      }
      return std::make_shared<TlsReceiver<MessageT>>(
          io_ctx, options.tls_config.value(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip.value()),
              options.local_port),
          message_cb, callback_handler);
    }
    case Scheme::UDP: {
      if (!options.local_ip) {
        throw TransportException("Local IP is required for UDP scheme");
      }
      auto socket = std::make_unique<boost::asio::ip::udp::socket>(
          *io_ctx,
          boost::asio::ip::udp::endpoint(
              boost::asio::ip::address::from_string(options.local_ip.value()),
              options.local_port));
      return std::make_shared<UdpReceiver<MessageT>>(
          std::move(socket), message_cb, callback_handler);
    }
    case Scheme::UDP_BROADCAST: {
      // listen on all interfaces: 0.0.0.0
      auto socket = std::make_unique<boost::asio::ip::udp::socket>(
          *io_ctx, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(),
                                                  options.local_port));
      return std::make_shared<UdpReceiver<MessageT>>(
          std::move(socket), message_cb, callback_handler);
    }
    case Scheme::UDP_MULTICAST: {
      // Parse and validate the address
      if (!options.local_ip) {
        throw TransportException(
            "Local IP is required for UDP_MULTICAST scheme");
      }
      auto multicast_addr =
          boost::asio::ip::make_address(options.local_ip.value());
      if (!multicast_addr.is_multicast()) {
        throw TransportException(
            "Provided address is not a valid multicast address");
      }

      if (multicast_addr.is_v6()) {
        boost::asio::ip::udp::endpoint listen_endpoint(
            boost::asio::ip::udp::v6(), options.local_port);

        auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io_ctx);
        socket->open(boost::asio::ip::udp::v6());

        socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
        socket->bind(listen_endpoint);

        // Specify the interface index (e.g., eth0 = 2)
        // 0 means "let OS choose default"
        socket->set_option(boost::asio::ip::multicast::join_group(
            multicast_addr.to_v6(), options.ipv6_interface.value_or(0)));

        return std::make_shared<UdpReceiver<MessageT>>(
            std::move(socket), message_cb, callback_handler);
      }
      auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io_ctx);
      socket->open(boost::asio::ip::udp::v4());

      // Allow multiple listeners on the same port
      socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
      socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(),
                                                  options.local_port));

      // Join multicast group
      socket->set_option(
          boost::asio::ip::multicast::join_group(multicast_addr.to_v4()));

      return std::make_shared<UdpReceiver<MessageT>>(
          std::move(socket), message_cb, callback_handler);
    }
    default:
      throw TransportException("Control fell through for make_receiver" +
                               std::to_string(static_cast<int>(scheme)));
  }
}
}  // namespace simpleio::transports::ip
