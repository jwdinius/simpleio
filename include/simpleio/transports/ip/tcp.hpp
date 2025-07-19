// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip::tcp {

/// @brief Create a TCP endpoint
/// @param ip_address, IP (v4 or v6) address
/// @param port, port number
/// @return TCP endpoint
boost::asio::ip::tcp::endpoint create_endpoint(const char* ip_address,
                                               uint16_t port) {
  return {boost::asio::ip::address::from_string(ip_address), port};
}

/// @brief Strategy for sending messages over TCP
/// @details This class uses a TCP socket to send messages of type MessageT
///          to a specified remote endpoint.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender : public simpleio::Sender<MessageT>,
               public std::enable_shared_from_this<Sender<MessageT>> {
 public:
  /// @brief Construct from a shared io_context and a remote endpoint.
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit Sender(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                  boost::asio::ip::tcp::endpoint remote_endpoint)
      : socket_(*io_ctx),
        remote_endpoint_(std::move(remote_endpoint)),
        strand_(boost::asio::make_strand(*io_ctx)) {}

  /// @brief Send a message.
  /// @details This method connects to the remote endpoint and sends the message
  ///          asynchronously.
  /// @param msg, the message to send.
  void send(MessageT const& msg) override {
    connect();
    auto self = this->shared_from_this();
    auto const& blob = msg.blob();
    boost::asio::async_write(
        socket_, boost::asio::buffer(blob.data(), blob.size()),
        boost::asio::bind_executor(
            strand_,
            [self](boost::system::error_code err_code, size_t bytes_sent) {
              if (!err_code) {
                BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes "
                                         << " to " << self->remote_endpoint_;
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "Error sending data: " << err_code.message();
              }
            }));
    socket_.close();
  }

 private:
  /// @brief Connect to the remote endpoint.
  void connect() {
    BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
    boost::system::error_code err_code;
    // TODO(jdinius): replace with async_connect
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
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
};

/// @brief Strategy for receiving messages over TCP
/// @details This class uses a TCP socket to receive messages of type MessageT
///          from a specified remote endpoint. Messages received are processed
///          by a callback function.
/// @tparam MessageT, the type of message to receive.
/// @tparam F, the type of callback function to execute when a message is
///          received.
template <typename MessageT>
class Receiver : public simpleio::Receiver<MessageT>,
                 public std::enable_shared_from_this<Receiver<MessageT>> {
 public:
  /// @brief Construct from a shared io_context and a local endpoint
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  explicit Receiver(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename simpleio::Receiver<MessageT>::callback_t message_cb)
      : acceptor_(*io_ctx, local_endpoint),
        strand_(boost::asio::make_strand(*io_ctx)),
        simpleio::Receiver<MessageT>(std::move(message_cb)) {}

  /// @brief Factory function to create a tcp::Receiver.
  /// @details Constructs a receiver and starts accepting connections
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @return A shared pointer to an initialized tcp::Receiver.
  static std::shared_ptr<Receiver<MessageT>> create(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb) {
    auto receiver = std::make_shared<Receiver<MessageT>>(io_ctx, local_endpoint,
                                                         std::move(message_cb));
    receiver->start_accepting();
    return receiver;
  }

  /// @brief Destructor
  /// @details This destructor closes the acceptor socket to stop accepting new
  ///          connections.
  /// @throw std::exception, if an error occurs while closing the acceptor.
  ~Receiver() {
    try {
      acceptor_.close();
    } catch (std::exception const& e) {
      BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
    }
  }

 protected:
  /// @brief Handle a received message.
  /// @details This function is called when a message is received.
  /// @param message, the received message.
  void on_read(MessageT const& message) override {
    auto self = this->shared_from_this();
    boost::asio::dispatch(strand_,
                          [self, message]() { self->message_cb_(message); });
  }

 private:
  /// @brief Start accepting incoming connections.
  /// @details This method sets up an asynchronous accept operation to listen
  ///          for incoming connections. When a connection is accepted, it
  ///          starts receiving messages from the connected socket.
  void start_accepting() {
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(
        acceptor_.get_executor());
    auto self = this->shared_from_this();
    acceptor_.async_accept(
        *socket,
        boost::asio::bind_executor(
            strand_, [self, socket](boost::system::error_code err_code) {
              if (!err_code) {
                BOOST_LOG_TRIVIAL(info) << "Accepted connection from peer at "
                                        << socket->remote_endpoint();
                self->start_receiving(socket);
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "Accept failed: " << err_code.message();
              }
              self->start_accepting();
            }));
  }

  /// @brief  Start receiving messages from a socket provisioned to receive
  /// them.
  /// @param socket, a shared pointer to the socket to receive messages from.
  void start_receiving(
      std::shared_ptr<boost::asio::ip::tcp::socket> const& socket) {
    auto buffer = std::make_shared<std::string>(MessageT::max_blob_size, '\0');
    auto self = this->shared_from_this();
    boost::asio::async_read(
        *socket, boost::asio::buffer(buffer->data(), buffer->size()),
        boost::asio::bind_executor(
            strand_, [self, buffer, socket](boost::system::error_code err_code,
                                            size_t bytes_recvd) {
              // We expect the client to close the connection after sending a
              // message i.e., "Open-Squirt-Close" for the simplest case
              if (err_code == boost::asio::error::eof && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug)
                    << "Received " << bytes_recvd << " bytes.";
                buffer->resize(bytes_recvd);
                self->on_read(MessageT(*buffer));
                self->start_receiving(socket);
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "Error receiving data: " << err_code.message();
              }
            }));
  }

  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
};

}  // namespace simpleio::transports::ip::tcp
