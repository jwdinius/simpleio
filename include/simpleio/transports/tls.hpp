// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <filesystem>
#include <memory>
#include <stdexcept>

#include "simpleio/transport.hpp"

namespace simpleio::transports {

/// @brief Configuration for TLS v1.3 transport.
/// @details This struct holds the paths to the Certificate Authority (CA) file,
///          the certificate file, and the private key file.
struct TlsConfig {
  std::filesystem::path ca_file;
  std::filesystem::path cert_file;
  std::filesystem::path key_file;
};

/// @brief Strategy for sending messages over TLS v1.3.
class TlsSendStrategy : public SendStrategy {
 public:
  /// @brief Construct from a shared io_context, a TLS configuration, and a
  /// remote endpoint.
  /// @param io_ctx, the shared io_context.
  /// @param tls_config, the TLS configuration to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  /// @throw std::runtime_error, if an error occurs while setting up the SSL
  /// context.
  explicit TlsSendStrategy(std::shared_ptr<boost::asio::io_context> io_ctx,
                           TlsConfig const& tls_config,
                           boost::asio::ip::tcp::endpoint remote_endpoint);

  /// @brief Send a byte vector securely.
  /// @param blob, the byte vector to send.
  void send(std::vector<std::byte> const& blob) override;

 private:
  void connect();
  void close();

  std::shared_ptr<boost::asio::io_context> const io_ctx_;
  boost::asio::ssl::context ssl_ctx_;
  std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
      socket_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
};

/// @brief Strategy for receiving messages over TLS v1.3.
class TlsReceiveStrategy : public ReceiveStrategy {
 public:
  /// @brief Construct from a shared io_context, a TLS configuration, a local
  /// endpoint, and a maximum blob size.
  /// @param io_ctx, the shared io_context.
  /// @param tls_config, the TLS configuration to use.
  /// @param local_endpoint, the local endpoint to listen on.
  /// @param max_blob_size, the maximum size of the allocated receive buffer.
  /// @throw std::runtime_error, if an error occurs while setting up the SSL
  /// context.
  TlsReceiveStrategy(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                     TlsConfig const& tls_config,
                     boost::asio::ip::tcp::endpoint const& local_endpoint,
                     size_t const& max_blob_size);

  /// @brief Destructor
  ~TlsReceiveStrategy() override;

 private:
  void start_accepting();
  void start_handshake(std::shared_ptr<boost::asio::ssl::stream<
                           boost::asio::ip::tcp::socket>> const& socket);
  void start_receiving(std::shared_ptr<boost::asio::ssl::stream<
                           boost::asio::ip::tcp::socket>> const& socket);

  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::ssl::context ssl_ctx_;
  size_t const max_blob_size_;
};

}  // namespace simpleio::transports
