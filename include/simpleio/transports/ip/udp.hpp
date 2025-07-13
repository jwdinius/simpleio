// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

/// @brief Strategy for sending messages over UDP (User Datagram Protocol).
/// @details This class uses a UDP socket to send messages of type MessageT
///          to a specified remote endpoint.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class UdpSender : public Sender<MessageT>,
                  public std::enable_shared_from_this<UdpSender<MessageT>> {
  using executor_type = typename boost::asio::ip::udp::socket::executor_type;

 public:
  /// @brief Construct from an io_context and a remote endpoint.
  /// @param socket, the (possibly shared) socket to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit UdpSender(std::shared_ptr<boost::asio::ip::udp::socket> socket,
                     boost::asio::ip::udp::endpoint remote_endpoint)
      : socket_(std::move(socket)),
        remote_endpoint_(std::move(remote_endpoint)),
        strand_(boost::asio::make_strand(socket_->get_executor())) {
    BOOST_LOG_TRIVIAL(debug)
        << "Configuring the socket to send to " << remote_endpoint_;
    if (!socket_->is_open()) {
      socket_->open(remote_endpoint_.protocol());
    }
    BOOST_LOG_TRIVIAL(debug)
        << "Socket is open? " << socket_->is_open()
        << " Local endpoint: " << socket_->local_endpoint();
  }

  /// @brief Factory function to create a UdpSender.
  /// @param socket, the (possibly shared) socket to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  /// @return A shared pointer to the created UdpSender.
  static std::shared_ptr<UdpSender<MessageT>> create(
      std::shared_ptr<boost::asio::ip::udp::socket> socket,
      boost::asio::ip::udp::endpoint remote_endpoint) {
    return std::make_shared<UdpSender<MessageT>>(std::move(socket),
                                                 std::move(remote_endpoint));
  }

  /// @brief Destructor.
  /// @details This destructor closes the socket if it is open, catching any
  ///          exceptions that may occur during closure.
  ~UdpSender() override {
    try {
      if (socket_->is_open()) {
        socket_->close();
      }
    } catch (std::exception const& e) {
      BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
    }
  }

  /// @brief Send a message.
  /// @details This method connects to the remote endpoint and sends the message
  ///          asynchronously.
  /// @param msg, the message to send.
  void send(MessageT const& msg) override {
    auto const& blob = msg.blob();
    auto self = this->shared_from_this();
    socket_->async_send_to(
        boost::asio::buffer(blob), remote_endpoint_,
        [self](boost::system::error_code err_code, size_t bytes_sent) {
          if (!err_code) {
            BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes to "
                                     << self->remote_endpoint_;
          } else {
            BOOST_LOG_TRIVIAL(error)
                << "Error sending data: " << err_code.message();
          }
        });
  }

 private:
  std::shared_ptr<boost::asio::ip::udp::socket> socket_;
  boost::asio::ip::udp::endpoint const remote_endpoint_;
  boost::asio::strand<executor_type> strand_;
};

/// @brief Strategy for asynchronously receiving messages of templated type
///        over UDP (User Datagram Protocol).
/// @details This class uses a UDP socket to receive messages of type MessageT
///          from a specified remote endpoint. Messages received are processed
///          by a callback function.
/// @tparam MessageT, the type of message to receive.
/// @tparam F, the type of callback function to execute when a message is
///          received.
template <typename MessageT>
class UdpReceiver : public Receiver<MessageT>,
                    public std::enable_shared_from_this<UdpReceiver<MessageT>> {
  using executor_type = typename boost::asio::ip::udp::socket::executor_type;

 public:
  /// @brief Construct from a shared io_context and a local endpoint
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  explicit UdpReceiver(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                       boost::asio::ip::udp::endpoint const& local_endpoint,
                       typename Receiver<MessageT>::callback_t message_cb)
      : socket_(std::make_unique<boost::asio::ip::udp::socket>(*io_ctx,
                                                               local_endpoint)),
        strand_(boost::asio::make_strand(*io_ctx)),
        Receiver<MessageT>(std::move(message_cb)) {
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
  }

  /// @brief Factory function to create a UdpReceiver.
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @return A shared pointer to the created UdpReceiver.
  static std::shared_ptr<UdpReceiver<MessageT>> create(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb) {
    auto receiver = std::make_shared<UdpReceiver<MessageT>>(
        io_ctx, local_endpoint, std::move(message_cb));
    receiver->start_receiving();
    return receiver;
  }

  /// @brief Construct from a shared io_context and a socket.
  /// @param io_ctx, the shared io_context.
  /// @param socket, a configured socket to listen to.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  explicit UdpReceiver(std::unique_ptr<boost::asio::ip::udp::socket> socket,
                       typename Receiver<MessageT>::callback_t message_cb)
      : socket_(std::move(socket)),
        strand_(boost::asio::make_strand(socket_->get_executor())),
        Receiver<MessageT>(std::move(message_cb)) {
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
  }

  /// @brief Factory function to create a UdpReceiver.
  /// @param socket, a configured socket to listen to.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @return A shared pointer to the created UdpReceiver.
  static std::shared_ptr<UdpReceiver<MessageT>> create(
      std::unique_ptr<boost::asio::ip::udp::socket> socket,
      typename Receiver<MessageT>::callback_t message_cb) {
    auto receiver = std::make_shared<UdpReceiver<MessageT>>(
        std::move(socket), std::move(message_cb));
    receiver->start_receiving();
    return receiver;
  }

  /// @brief Destructor.
  /// @details This destructor closes the socket if it is open, catching any
  ///          exceptions that may occur during closure.
  ~UdpReceiver() override {
    try {
      socket_->close();
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
  /// @brief Start receiving messages asynchronously.
  void start_receiving() {
    auto buffer = std::make_shared<std::string>(MessageT::max_blob_size, '\0');
    auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();
    auto self = this->shared_from_this();
    socket_->async_receive_from(
        boost::asio::buffer(*buffer), *remote_endpoint,
        boost::asio::bind_executor(
            strand_,
            [self, buffer, remote_endpoint](boost::system::error_code err_code,
                                            size_t bytes_recvd) {
              if (!err_code && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd
                                         << " bytes from " << *remote_endpoint;
                buffer->resize(bytes_recvd);
                self->on_read(MessageT(*buffer));
                self->start_receiving();
              } else {
                // Handle the error
                BOOST_LOG_TRIVIAL(error)
                    << "Error receiving data: " << err_code.message();
              }
            }));
    BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
  }

  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
  boost::asio::strand<executor_type> strand_;
};
}  // namespace simpleio::transports::ip
