// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/tls.hpp"

#include <boost/log/trivial.hpp>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::TlsSendStrategy::TlsSendStrategy(
    std::shared_ptr<boost::asio::io_context> io_ctx,
    siotrns::TlsConfig const& tls_config,
    boost::asio::ip::tcp::endpoint remote_endpoint)
    : io_ctx_(std::move(io_ctx)),
      remote_endpoint_(std::move(remote_endpoint)),
      ssl_ctx_(boost::asio::ssl::context::tlsv13),
      socket_(std::make_unique<
              boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
          *io_ctx_, ssl_ctx_)) {
  try {
    ssl_ctx_.load_verify_file(tls_config.ca_file.string());
    ssl_ctx_.use_certificate_chain_file(tls_config.cert_file.string());
    ssl_ctx_.use_private_key_file(tls_config.key_file.string(),
                                  boost::asio::ssl::context::pem);
  } catch (std::exception const& e) {
    std::ostringstream error_stream;
    error_stream << "Error setting up TLSv1.3 context: " << e.what();
    BOOST_LOG_TRIVIAL(error) << error_stream.str();
    throw std::runtime_error(error_stream.str());
  }
}

void siotrns::TlsSendStrategy::send(std::vector<std::byte> const& blob) {
  connect();
  boost::asio::async_write(
      *socket_, boost::asio::buffer(blob),
      [this](boost::system::error_code err_code, std::size_t bytes_sent) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent
                                   << " bytes securely to " << remote_endpoint_;
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "Error sending data: " << err_code.message();
        }
      });
  close();
}

void siotrns::TlsSendStrategy::connect() {
  BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
  // Reset the socket to reuse the existing SSL context
  socket_ =
      std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
          *io_ctx_, ssl_ctx_);
  socket_->lowest_layer().open(boost::asio::ip::tcp::v4());

  // Attempt to establish a new connection
  boost::system::error_code err_code;
  socket_->lowest_layer().connect(remote_endpoint_, err_code);
  if (!err_code) {
    BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;

    // Perform TLS handshake
    socket_->handshake(boost::asio::ssl::stream_base::client, err_code);
    if (!err_code) {
      BOOST_LOG_TRIVIAL(debug) << "TLSv1.3 Handshake successful!";
    } else {
      BOOST_LOG_TRIVIAL(error)
          << "TLSv1.3 Handshake failed: " << err_code.message();
    }
  } else {
    BOOST_LOG_TRIVIAL(error) << "Failed to connect: " << err_code.message();
  }
  BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
}

void siotrns::TlsSendStrategy::close() {
  BOOST_LOG_TRIVIAL(debug) << "Closing connection to " << remote_endpoint_;
  boost::system::error_code err_code;
  socket_->shutdown(err_code);
  socket_.reset();
  BOOST_LOG_TRIVIAL(debug) << "Closed connection to " << remote_endpoint_;
}

siotrns::TlsReceiveStrategy::TlsReceiveStrategy(
    std::shared_ptr<boost::asio::io_context> const& io_ctx,
    TlsConfig const& tls_config,
    boost::asio::ip::tcp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
    : acceptor_(*io_ctx, local_endpoint),
      ssl_ctx_(boost::asio::ssl::context::tlsv13),
      max_blob_size_(max_blob_size) {
  try {
    ssl_ctx_.load_verify_file(tls_config.ca_file.string());
    ssl_ctx_.use_certificate_chain_file(tls_config.cert_file.string());
    ssl_ctx_.use_private_key_file(tls_config.key_file.string(),
                                  boost::asio::ssl::context::pem);
  } catch (std::exception const& e) {
    std::ostringstream error_stream;
    error_stream << "Error setting up TLSv1.3 context: " << e.what();
    BOOST_LOG_TRIVIAL(error) << error_stream.str();
    throw std::runtime_error(error_stream.str());
  }

  start_accepting();
}

siotrns::TlsReceiveStrategy::~TlsReceiveStrategy() {
  try {
    acceptor_.close();
  } catch (std::exception const& e) {
    BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
  }
}

void siotrns::TlsReceiveStrategy::start_accepting() {
  auto socket =
      std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
          acceptor_.get_executor(), ssl_ctx_);
  acceptor_.async_accept(
      socket->lowest_layer(),
      [this, socket](boost::system::error_code err_code) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(info) << "Accepted secure connection from "
                                  << socket->lowest_layer().remote_endpoint();
          start_handshake(socket);
        } else {
          BOOST_LOG_TRIVIAL(error) << "Accept failed: " << err_code.message();
        }
        start_accepting();  // Keep listening for new connections
      });
}

void siotrns::TlsReceiveStrategy::start_handshake(
    std::shared_ptr<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> const& socket) {
  socket->async_handshake(
      boost::asio::ssl::stream_base::server,
      [this, socket](boost::system::error_code err_code) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(debug) << "TLSv1.3 handshake successful!";
          start_receiving(socket);
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "TLSv1.3 handshake failed: " << err_code.message();
        }
      });
}

void siotrns::TlsReceiveStrategy::start_receiving(
    std::shared_ptr<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> const& socket) {
  auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);

  boost::asio::async_read(
      *socket, boost::asio::buffer(*buffer),
      [this, buffer, socket](boost::system::error_code err_code,
                             size_t bytes_recvd) {
        if (err_code == boost::asio::error::eof && bytes_recvd > 0) {
          BOOST_LOG_TRIVIAL(debug)
              << "Received " << bytes_recvd << " bytes securely.";
          buffer->resize(bytes_recvd);
          this->blob_queue_.push(std::move(*buffer));
          start_receiving(socket);
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "Error receiving data: " << err_code.message();
        }
      });
}
