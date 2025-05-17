// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <string>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

/// @brief Strategy for asynchronously sending messages over UDP
///        (User Datagram Protocol).
class UdpSendStrategy : public SendStrategy {
 public:
  /// @brief Construct from an io_context and a remote endpoint.
  /// @param socket, the (possibly shared) socket to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit UdpSendStrategy(std::shared_ptr<boost::asio::ip::udp::socket> socket,
                           boost::asio::ip::udp::endpoint remote_endpoint);

  ~UdpSendStrategy() override;

  /// @brief Send a string.
  /// @param blob, the string to send.
  void send(std::string const& blob) override;

 private:
  std::shared_ptr<boost::asio::ip::udp::socket> socket_;
  boost::asio::ip::udp::endpoint const remote_endpoint_;
};

/// @brief Strategy for asynchronously receiving messages of templated type
///        over UDP (User Datagram Protocol).
class UdpReceiveStrategy : public ReceiveStrategy {
 public:
  /// @brief Construct from an io_context, a local endpoint, and a serializer.
  /// @param io_ctx, the io_context to use.
  /// @param local_endpoint, the local endpoint to listen on.
  /// @param max_blob_size, packet frame size (in bytes).
  explicit UdpReceiveStrategy(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint const& local_endpoint,
      size_t const& max_blob_size);

  /// @brief Construct from an io_context, a socket, and a serializer.
  /// @param socket, a configured socket to listen to.
  /// @param max_blob_size, packet frame size (in bytes).
  explicit UdpReceiveStrategy(
      std::unique_ptr<boost::asio::ip::udp::socket> socket,
      size_t const& max_blob_size);

  /// @brief Destructor.
  ~UdpReceiveStrategy() override;

 private:
  void start_receiving();

  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
  size_t const max_blob_size_;
};
}  // namespace simpleio::transports::ip
