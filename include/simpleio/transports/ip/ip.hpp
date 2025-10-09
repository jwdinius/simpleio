// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "simpleio/message.hpp"
#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/detail/ip.hpp"
#include "simpleio/transports/ip/http.hpp"
#include "simpleio/transports/ip/https.hpp"
#include "simpleio/transports/ip/tcp.hpp"
#include "simpleio/transports/ip/tls.hpp"
#include "simpleio/transports/ip/typedefs.hpp"
#include "simpleio/transports/ip/udp.hpp"

namespace simpleio::transports::ip {

/// @brief Context to create IP-based transports.
/// @details A Context sets up a shared task scheduler, lifecycle manager,
///          and callback executor for sending and receiving messages over
///          network interfaces within a single process.
class Context {
 public:
  /// @brief Default constructor
  /// @details Creates an io context running on a single thread
  Context() : impl_(std::make_unique<detail::Context>()) {}

  /// @brief Constructor specifying number of threads for io context
  explicit Context(uint8_t num_threads)
      : impl_(std::make_unique<detail::Context>(num_threads)) {}

  /// @brief Destructor.
  ~Context() {
    impl_.reset();
  }

  template <typename MessageT>
  std::shared_ptr<simpleio::Sender<MessageT>> create_sender(
      Options const& options) {
    return impl_->create_sender<MessageT>(options);
  }

  template <typename MessageT>
  std::shared_ptr<simpleio::Receiver<MessageT>> create_receiver(
      Options const& options,
      typename simpleio::Receiver<MessageT>::callback_t message_cb) {
    return impl_->create_receiver<MessageT>(options, std::move(message_cb));
  }

  template <typename ServiceT>
  std::shared_ptr<simpleio::Client<ServiceT>> create_client(
      ServiceOptions const& options) {
    return impl_->create_client<ServiceT>(options);
  }

  template <typename ServiceT>
  std::shared_ptr<simpleio::Server<ServiceT>> create_server(
      ServiceOptions const& options,
      typename simpleio::Server<ServiceT>::request_callback_t request_cb) {
    return impl_->create_server<ServiceT>(options, std::move(request_cb));
  }

 private:
  std::unique_ptr<detail::Context> impl_;
};
}  // namespace simpleio::transports::ip
