// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/tcp.hpp"

#include <boost/log/trivial.hpp>
#include <memory>
#include <utility>

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::TcpSendStrategy::TcpSendStrategy(
    std::shared_ptr<boost::asio::io_context> const& io_ctx,
    boost::asio::ip::tcp::endpoint remote_endpoint)
    : socket_(*io_ctx), remote_endpoint_(std::move(remote_endpoint)) {}

void siotrns::TcpSendStrategy::send(std::vector<std::byte> const& blob) {
  connect();
  boost::asio::async_write(
      socket_, boost::asio::buffer(blob),
      [this](boost::system::error_code err_code, std::size_t bytes_sent) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes "
                                   << " to " << remote_endpoint_;
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "Error sending data: " << err_code.message();
        }
      });
  socket_.close();
}

void siotrns::TcpSendStrategy::connect() {
  BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
  boost::system::error_code err_code;
  socket_.connect(remote_endpoint_, err_code);
  if (!err_code) {
    BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
  } else {
    BOOST_LOG_TRIVIAL(error) << "Failed to connect: " << err_code.message();
  }
  BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
}

siotrns::TcpReceiveStrategy::TcpReceiveStrategy(
    std::shared_ptr<boost::asio::io_context> const& io_ctx,
    boost::asio::ip::tcp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
    : acceptor_(*io_ctx, local_endpoint), max_blob_size_(max_blob_size) {
  start_accepting();
}

siotrns::TcpReceiveStrategy::~TcpReceiveStrategy() {
  try {
    acceptor_.close();
  } catch (std::exception const& e) {
    BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
  }
}

void siotrns::TcpReceiveStrategy::start_accepting() {
  auto socket =
      std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
  acceptor_.async_accept(
      *socket, [this, socket](boost::system::error_code err_code) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(info) << "Accepted connection from peer at "
                                  << socket->remote_endpoint();
          start_receiving(socket);
        } else {
          BOOST_LOG_TRIVIAL(error) << "Accept failed: " << err_code.message();
        }
        start_accepting();
      });
}

void siotrns::TcpReceiveStrategy::start_receiving(
    std::shared_ptr<boost::asio::ip::tcp::socket> const& socket) {
  auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);

  boost::asio::async_read(
      *socket, boost::asio::buffer(*buffer),
      [this, buffer, socket](boost::system::error_code err_code,
                             size_t bytes_recvd) {
        // We expect the client to close the connection after sending a message
        // i.e., "Open-Squirt-Close" for the simplest case
        if (err_code == boost::asio::error::eof && bytes_recvd > 0) {
          BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes.";
          buffer->resize(bytes_recvd);
          this->blob_queue_.push(std::move(*buffer));
          start_receiving(socket);
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "Error receiving data: " << err_code.message();
        }
      });
}
