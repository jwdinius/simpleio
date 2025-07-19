// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip::udp {

/// @brief Create a UDP endpoint
/// @param ip_address, IP (v4 or v6) address
/// @param port, port number
/// @return UDP endpoint
boost::asio::ip::udp::endpoint create_endpoint(const char* ip_address,
                                               uint16_t port) {
  return {boost::asio::ip::address::from_string(ip_address), port};
}

/// @brief Strategy for sending messages over UDP (User Datagram Protocol).
/// @details This class uses a UDP socket to send messages of type MessageT
///          to a specified remote endpoint.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender : public simpleio::Sender<MessageT>,
               public std::enable_shared_from_this<Sender<MessageT>> {
  using executor_type = typename boost::asio::ip::udp::socket::executor_type;

 public:
  /// @brief Construct from an io_context and a remote endpoint.
  /// @param socket, the (possibly shared) socket to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit Sender(std::shared_ptr<boost::asio::ip::udp::socket> socket,
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

  /// @brief Factory function to create a udp::Sender.
  /// @details Constructs a (unicast) receiver
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, endpoint to send messages to.
  /// @return A shared pointer to an initialized tcp::Sender.
  static std::shared_ptr<Sender<MessageT>> create_unicast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint remote_endpoint) {
    auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);
    return std::make_shared<Sender<MessageT>>(std::move(socket),
                                              remote_endpoint);
  }

  /// @brief Factory function to create a udp::Sender.
  /// @details Constructs a (broadcast) receiver
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, broadcast endpoint to send messages to.
  /// @return A shared pointer to an initialized tcp::Sender.
  /// @throw TransportException if address is not IPv4
  static std::shared_ptr<Sender<MessageT>> create_broadcast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint remote_endpoint) {
    auto const& addr = remote_endpoint.address();
    if (!addr.is_v4()) {
      throw TransportException("Broadcast only supported for IPv4.");
    }
    auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);
    socket->open(boost::asio::ip::udp::v4());
    socket->set_option(boost::asio::socket_base::broadcast(true));
    return std::make_shared<Sender<MessageT>>(socket, remote_endpoint);
  }

  /// @brief Factory function to create a udp::Sender.
  /// @details Constructs a (multicast) receiver
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, multicast endpoint to send messages to.
  /// @return A shared pointer to an initialized tcp::Sender.
  /// @throw TransportException if address is not a multicast address
  static std::shared_ptr<Sender<MessageT>> create_multicast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint remote_endpoint, uint8_t hops,
      bool loopback, uint8_t interface_v6 = 0) {
    auto const& addr = remote_endpoint.address();
    if (!addr.is_multicast()) {
      throw TransportException(
          "Provided address is not a valid multicast address");
    }

    auto socket = std::make_shared<boost::asio::ip::udp::socket>(*io_ctx);
    if (addr.is_v4()) {
      socket->open(boost::asio::ip::udp::v4());
    } else if (addr.is_v6()) {
      socket->open(boost::asio::ip::udp::v6());
      // Specify the interface index (e.g., eth0 = 2)
      // 0 means "let OS choose default"
      socket->set_option(
          boost::asio::ip::multicast::join_group(addr.to_v6(), interface_v6));
    } else {
      throw TransportException("Invalid multicast address: must be v4 or v6");
    }

    socket->set_option(boost::asio::ip::multicast::hops(hops));
    socket->set_option(boost::asio::ip::multicast::enable_loopback(loopback));
    return std::make_shared<Sender<MessageT>>(socket, remote_endpoint);
  }

  /// @brief Destructor.
  /// @details This destructor closes the socket if it is open, catching any
  ///          exceptions that may occur during closure.
  ~Sender() override {
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
class Receiver : public simpleio::Receiver<MessageT>,
                 public std::enable_shared_from_this<Receiver<MessageT>> {
  using executor_type = typename boost::asio::ip::udp::socket::executor_type;

 public:
  /// @brief Construct from a shared io_context and a socket.
  /// @param socket, a configured socket to listen to.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  explicit Receiver(
      std::unique_ptr<boost::asio::ip::udp::socket> socket,
      typename simpleio::Receiver<MessageT>::callback_t message_cb)
      : socket_(std::move(socket)),
        strand_(boost::asio::make_strand(socket_->get_executor())),
        simpleio::Receiver<MessageT>(std::move(message_cb)) {
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
  }

  /// @brief Factory function to create a Receiver.
  /// @param io_ctx, the shared io_context.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @return A shared pointer to the created Receiver.
  static std::shared_ptr<Receiver<MessageT>> create_unicast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb) {
    auto socket =
        std::make_unique<boost::asio::ip::udp::socket>(*io_ctx, local_endpoint);
    auto receiver = std::make_shared<Receiver<MessageT>>(std::move(socket),
                                                         std::move(message_cb));
    receiver->start_receiving();
    return receiver;
  }

  static std::shared_ptr<Receiver<MessageT>> create_broadcast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      uint16_t local_port, typename Receiver<MessageT>::callback_t message_cb) {
    auto socket = std::make_unique<boost::asio::ip::udp::socket>(
        *io_ctx,
        boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), local_port));
    auto receiver = std::make_shared<Receiver<MessageT>>(std::move(socket),
                                                         std::move(message_cb));
    receiver->start_receiving();
    return receiver;
  }

  static std::shared_ptr<Receiver<MessageT>> create_multicast(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::udp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb,
      uint8_t interface_v6 = 0) {
    auto const& addr = local_endpoint.address();
    if (!addr.is_multicast()) {
      throw TransportException(
          "Provided address is not a valid multicast address");
    }

    if (addr.is_v6()) {
      boost::asio::ip::udp::endpoint listen_endpoint(boost::asio::ip::udp::v6(),
                                                     local_endpoint.port());
      auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io_ctx);
      socket->open(boost::asio::ip::udp::v6());
      socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
      socket->bind(listen_endpoint);
      // Specify the interface index (e.g., eth0 = 2)
      // 0 means "let OS choose default"
      socket->set_option(
          boost::asio::ip::multicast::join_group(addr.to_v6(), interface_v6));
      auto receiver = std::make_shared<Receiver<MessageT>>(
          std::move(socket), std::move(message_cb));
      receiver->start_receiving();
      return receiver;
    }
    auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io_ctx);
    socket->open(boost::asio::ip::udp::v4());
    // Allow multiple listeners on the same port
    socket->set_option(boost::asio::ip::udp::socket::reuse_address(true));
    socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(),
                                                local_endpoint.port()));
    // Join multicast group
    socket->set_option(boost::asio::ip::multicast::join_group(addr.to_v4()));

    auto receiver = std::make_shared<Receiver<MessageT>>(std::move(socket),
                                                         std::move(message_cb));
    receiver->start_receiving();
    return receiver;
  }

  /// @brief Destructor.
  /// @details This destructor closes the socket if it is open, catching any
  ///          exceptions that may occur during closure.
  ~Receiver() override {
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
}  // namespace simpleio::transports::ip::udp
