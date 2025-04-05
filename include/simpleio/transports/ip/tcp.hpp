// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <memory>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

/// @brief Strategy for sending messages over TCP
class TcpSendStrategy : public SendStrategy {
 public:
  /// @brief Construct from a shared io_context and a remote endpoint.
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit TcpSendStrategy(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint remote_endpoint);

  /// @brief Send a byte vector.
  /// @param blob, the byte vector to send.
  void send(std::vector<std::byte> const& blob) override;

 private:
  void connect();

  boost::asio::ip::tcp::socket socket_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
};

/// @brief Strategy for receiving messages over TCP
class TcpReceiveStrategy : public ReceiveStrategy {
 public:
  /// @brief Construct from a shared io_context, a local endpoint, and a maximum
  /// blob size.
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param max_blob_size, maximum size of allocated receive buffer.
  explicit TcpReceiveStrategy(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      size_t const& max_blob_size);

  /// @brief Destructor
  ~TcpReceiveStrategy() override;

 private:
  void start_accepting();
  void start_receiving(
      std::shared_ptr<boost::asio::ip::tcp::socket> const& socket);

  boost::asio::ip::tcp::acceptor acceptor_;
  size_t const max_blob_size_;
};

}  // namespace simpleio::transports::ip
