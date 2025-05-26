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
class UdpSender : public Sender<MessageT> {
 public:
  /// @brief Construct from an io_context and a remote endpoint.
  /// @param socket, the (possibly shared) socket to use.
  /// @param remote_endpoint, the remote endpoint to send to.
  explicit UdpSender(std::shared_ptr<boost::asio::ip::udp::socket> socket,
                     boost::asio::ip::udp::endpoint remote_endpoint)
      : socket_(std::move(socket)),
        remote_endpoint_(std::move(remote_endpoint)) {
    BOOST_LOG_TRIVIAL(debug)
        << "Configuring the socket to send to " << remote_endpoint_;
    if (!socket_->is_open()) {
      socket_->open(remote_endpoint_.protocol());
    }
    BOOST_LOG_TRIVIAL(debug)
        << "Socket is open? " << socket_->is_open()
        << " Local endpoint: " << socket_->local_endpoint();
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
    auto send_fn = [this](boost::system::error_code err_code,
                          std::size_t bytes_sent) {
      if (!err_code) {
        BOOST_LOG_TRIVIAL(debug)
            << "Sent " << bytes_sent << " bytes to " << remote_endpoint_;
      } else {
        BOOST_LOG_TRIVIAL(error)
            << "Error sending data: " << err_code.message();
      }
    };
    socket_->async_send_to(boost::asio::buffer(blob), remote_endpoint_,
                           send_fn);
  }

 private:
  std::shared_ptr<boost::asio::ip::udp::socket> socket_;
  boost::asio::ip::udp::endpoint const remote_endpoint_;
};

/// @brief Strategy for asynchronously receiving messages of templated type
///        over UDP (User Datagram Protocol).
/// @details This class uses a UDP socket to receive messages of type MessageT
///          from a specified remote endpoint. Messages received are processed
///          by a callback function.
/// @tparam MessageT, the type of message to receive.
/// @tparam F, the type of callback function to execute when a message is
///          received.
template <typename MessageT, typename F = std::function<void(MessageT const&)>>
class UdpReceiver : public Receiver<MessageT, F> {
 public:
  /// @brief Construct from a shared io_context and a local endpoint
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  /// @param worker, the worker to use for processing messages.
  explicit UdpReceiver(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                       boost::asio::ip::udp::endpoint const& local_endpoint,
                       F message_cb,
                       std::shared_ptr<simpleio::Worker> const& worker)
      : Receiver<MessageT, F>(std::move(message_cb), worker) {
    socket_ =
        std::make_unique<boost::asio::ip::udp::socket>(*io_ctx, local_endpoint);
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
    start_receiving();
  }

  /// @brief Construct from a shared io_context and a socket.
  /// @param io_ctx, the shared io_context.
  /// @param socket, a configured socket to listen to.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  /// @param worker, the worker to use for processing messages.
  explicit UdpReceiver(std::unique_ptr<boost::asio::ip::udp::socket> socket,
                       F message_cb,
                       std::shared_ptr<simpleio::Worker> const& worker)
      : socket_(std::move(socket)),
        Receiver<MessageT, F>(std::move(message_cb), worker) {
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
    start_receiving();
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

 private:
  /// @brief Start receiving messages asynchronously.
  void start_receiving() {
    auto buffer = std::make_shared<std::string>(MessageT::max_blob_size, '\0');
    auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();

    socket_->async_receive_from(
        boost::asio::buffer(*buffer), *remote_endpoint,
        [this, buffer, remote_endpoint](boost::system::error_code err_code,
                                        size_t bytes_recvd) {
          if (!err_code && bytes_recvd > 0) {
            BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd
                                     << " bytes from " << *remote_endpoint;
            buffer->resize(bytes_recvd);
            this->on_read(MessageT(*buffer));
            start_receiving();
          } else {
            // Handle the error
            BOOST_LOG_TRIVIAL(error)
                << "Error receiving data: " << err_code.message();
          }
        });
    BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
  }

  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
};
}  // namespace simpleio::transports::ip
