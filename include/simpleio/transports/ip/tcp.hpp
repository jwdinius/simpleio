// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

/// @brief Strategy for sending messages over TCP
template <typename MessageT>
class TcpSender : public Sender<MessageT> {
 public:
  /// @brief Construct from a shared io_context and a remote endpoint.
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit TcpSender(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                     boost::asio::ip::tcp::endpoint remote_endpoint)
      : socket_(*io_ctx), remote_endpoint_(std::move(remote_endpoint)) {}

  void send(MessageT const& msg) override {
    connect();
    auto const& blob = msg.blob();
    boost::asio::async_write(
        socket_, boost::asio::buffer(blob.data(), blob.size()),
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

 private:
  void connect() {
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

  boost::asio::ip::tcp::socket socket_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
};

/// @brief Strategy for receiving messages over TCP
template <typename MessageT, typename F = std::function<void(MessageT const&)>>
class TcpReceiver : public Receiver<MessageT, F> {
 public:
  /// @brief Construct from a shared io_context, a local endpoint, and a maximum
  /// blob size.
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  explicit TcpReceiver(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                       boost::asio::ip::tcp::endpoint const& local_endpoint,
                       F message_cb,
                       std::shared_ptr<simpleio::Worker> const& worker)
      : acceptor_(*io_ctx, local_endpoint),
        Receiver<MessageT, F>(std::move(message_cb), worker) {
    start_accepting();
  }

  ~TcpReceiver() {
    try {
      acceptor_.close();
    } catch (std::exception const& e) {
      BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
    }
  }

 private:
  void start_accepting() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
        acceptor_.get_executor());
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

  void start_receiving(
      std::shared_ptr<boost::asio::ip::tcp::socket> const& socket) {
    auto buffer = std::make_shared<std::string>(MessageT::max_blob_size, '\0');

    boost::asio::async_read(
        *socket, boost::asio::buffer(buffer->data(), buffer->size()),
        [this, buffer, socket](boost::system::error_code err_code,
                               size_t bytes_recvd) {
          // We expect the client to close the connection after sending a
          // message i.e., "Open-Squirt-Close" for the simplest case
          if (err_code == boost::asio::error::eof && bytes_recvd > 0) {
            BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes.";
            buffer->resize(bytes_recvd);
            this->on_read(MessageT(*buffer));
            start_receiving(socket);
          } else {
            BOOST_LOG_TRIVIAL(error)
                << "Error receiving data: " << err_code.message();
          }
        });
  }

  boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace simpleio::transports::ip
