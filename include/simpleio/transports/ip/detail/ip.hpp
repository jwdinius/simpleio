// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

#include "simpleio/message.hpp"
#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/http.hpp"
#include "simpleio/transports/ip/https.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/typedefs.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip::detail {

class Context {
 public:
  /// @brief Default constructor
  /// @details Creates an io context running on a single thread
  Context();

  /// @brief Constructor specifying number of threads for io context
  explicit Context(uint8_t num_threads);

  /// @brief Destructor.
  ~Context();

  template <typename MessageT>
  std::shared_ptr<simpleio::Sender<MessageT>> create_sender(
      std::variant<TcpOptions, TlsOptions, UdpOptions> const& options) {
    if (std::holds_alternative<TcpOptions>(options)) {
      auto const& opts = std::get<TcpOptions>(options);
      return std::make_shared<tcp::Sender<MessageT>>(
          scheduler_,
          tcp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
          opts.framer, opts.streaming);
    } else if (std::holds_alternative<TlsOptions>(options)) {
      auto const& opts = std::get<TlsOptions>(options);
      return std::make_shared<tls::Sender<MessageT>>(
          scheduler_,
          tcp::create_endpoint(opts.tcp_options.endpoint.ip.c_str(),
                               opts.tcp_options.endpoint.port),
          opts.credentials, opts.tcp_options.framer,
          opts.tcp_options.streaming);
    } else {
      auto const& opts = std::get<UdpOptions>(options);
      if (opts.broadcast) {
        return udp::Sender<MessageT>::create_broadcast(
            scheduler_,
            udp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port));
      }
      if (opts.ttl.has_value()) {
        return udp::Sender<MessageT>::create_multicast(
            scheduler_,
            udp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
            opts.ttl.value(), opts.loopback.value_or(false),
            opts.interface_v6.value_or(0));
      }
      return udp::Sender<MessageT>::create_unicast(
          scheduler_,
          udp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port));
    }
  }

  template <typename MessageT>
  std::shared_ptr<simpleio::Receiver<MessageT>> create_receiver(
      std::variant<TcpOptions, TlsOptions, UdpOptions> const& options,
      typename simpleio::Receiver<MessageT>::callback_t message_cb) {
    if (std::holds_alternative<TcpOptions>(options)) {
      auto const& opts = std::get<TcpOptions>(options);
      return tcp::Receiver<MessageT>::create(
          scheduler_,
          tcp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
          std::move(message_cb), opts.framer);
    } else if (std::holds_alternative<TlsOptions>(options)) {
      auto const& opts = std::get<TlsOptions>(options);
      return tls::Receiver<MessageT>::create(
          scheduler_,
          tcp::create_endpoint(opts.tcp_options.endpoint.ip.c_str(),
                               opts.tcp_options.endpoint.port),
          std::move(message_cb), opts.credentials, opts.tcp_options.framer);
    } else {
      auto const& opts = std::get<UdpOptions>(options);
      if (opts.broadcast) {
        return udp::Receiver<MessageT>::create_broadcast(
            scheduler_, opts.endpoint.port, std::move(message_cb));
      }
      if (opts.ttl.has_value()) {
        return udp::Receiver<MessageT>::create_multicast(
            scheduler_,
            udp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
            std::move(message_cb), opts.interface_v6.value_or(0));
      }
      return udp::Receiver<MessageT>::create_unicast(
          scheduler_,
          udp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
          std::move(message_cb));
    }
  }

  template <typename ServiceT>
  std::shared_ptr<simpleio::Client<ServiceT>> create_client(
      ServiceOptions const& options) {
    if (std::holds_alternative<HttpOptions>(options)) {
      auto const& opts = std::get<HttpOptions>(options);
      return std::make_shared<http::Client<ServiceT>>(
          scheduler_,
          tcp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
          opts.timeout);
    } else {
      auto const& opts = std::get<HttpsOptions>(options);
      return std::make_shared<https::Client<ServiceT>>(
          scheduler_,
          tcp::create_endpoint(opts.http_options.endpoint.ip.c_str(),
                               opts.http_options.endpoint.port),
          opts.http_options.timeout, opts.credentials);
    }
  }

  template <typename ServiceT>
  std::shared_ptr<simpleio::Server<ServiceT>> create_server(
      ServiceOptions const& options,
      typename simpleio::Server<ServiceT>::request_callback_t request_cb) {
    if (std::holds_alternative<HttpOptions>(options)) {
      auto const& opts = std::get<HttpOptions>(options);
      return http::Server<ServiceT>::create(
          scheduler_,
          tcp::create_endpoint(opts.endpoint.ip.c_str(), opts.endpoint.port),
          std::move(request_cb), opts.timeout);
    } else {
      auto const& opts = std::get<HttpsOptions>(options);
      return https::Server<ServiceT>::create(
          scheduler_,
          tcp::create_endpoint(opts.http_options.endpoint.ip.c_str(),
                               opts.http_options.endpoint.port),
          std::move(request_cb), opts.http_options.timeout, opts.credentials);
    }
  }

 private:
  std::shared_ptr<boost::asio::io_context> scheduler_;
  std::unique_ptr<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      lifecycle_manager_;
  std::vector<std::thread> scheduler_threads_;
};
}  // namespace simpleio::transports::ip::detail
