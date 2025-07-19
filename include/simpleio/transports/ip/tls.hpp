// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/log/trivial.hpp>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip::tls {

/// @brief Credentials files for TLS v1.3 transport.
/// @details This struct holds the paths to the Certificate Authority (CA) file,
///          the certificate file, and the private key file.
struct Credentials {
  std::filesystem::path ca_file;
  std::filesystem::path cert_file;
  std::filesystem::path key_file;
};

/// @brief Strategy for sending messages over TLS v1.3.
/// @details This class uses a TCP socket to send messages of type MessageT
///          securely to a specified remote endpoint.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender : public simpleio::Sender<MessageT>,
               public std::enable_shared_from_this<Sender<MessageT>> {
 public:
  /// @brief Construct from a shared io_context, Credentials struct, and a
  /// remote endpoint.
  /// @param io_ctx, the shared io_context.
  /// @param remote_endpoint, the remote endpoint to send to.
  /// @param config, Credentials struct to use.
  /// @throw TransportException, if an error occurs while setting up the SSL
  /// context.
  explicit Sender(std::shared_ptr<boost::asio::io_context> io_ctx,
                  boost::asio::ip::tcp::endpoint remote_endpoint,
                  Credentials const& config)
      : io_ctx_(std::move(io_ctx)),
        remote_endpoint_(std::move(remote_endpoint)),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        socket_(std::make_unique<
                boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
            *io_ctx_, ssl_ctx_)),
        strand_(boost::asio::make_strand(*io_ctx_)) {
    try {
      ssl_ctx_.load_verify_file(config.ca_file.string());
      ssl_ctx_.use_certificate_chain_file(config.cert_file.string());
      ssl_ctx_.use_private_key_file(config.key_file.string(),
                                    boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream error_stream;
      error_stream << "Error setting up TLSv1.3 context: " << e.what();
      BOOST_LOG_TRIVIAL(error) << error_stream.str();
      throw TransportException(error_stream.str());
    }
  }

  /// @brief Send a message.
  /// @details This method connects to the remote endpoint and sends the message
  ///          securely and asynchronously.
  /// @param msg, the message to send.
  void send(MessageT const& msg) override {
    connect();
    auto self = this->shared_from_this();
    auto const& blob = msg.blob();
    boost::asio::async_write(
        *socket_, boost::asio::buffer(blob.data(), blob.size()),
        boost::asio::bind_executor(
            strand_,
            [self](boost::system::error_code err_code, size_t bytes_sent) {
              if (!err_code) {
                BOOST_LOG_TRIVIAL(debug)
                    << "Sent " << bytes_sent << " bytes securely to "
                    << self->remote_endpoint_;
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "Error sending data: " << err_code.message();
              }
            }));
    close();
  }

 private:
  /// @brief Connect to the remote endpoint.
  void connect() {
    BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
    // Reset the socket to reuse the existing SSL context
    socket_ = std::make_unique<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(*io_ctx_,
                                                                ssl_ctx_);
    socket_->lowest_layer().open(remote_endpoint_.protocol());

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

  /// @brief Close the connection.
  void close() {
    BOOST_LOG_TRIVIAL(debug) << "Closing connection to " << remote_endpoint_;
    boost::system::error_code err_code;
    socket_->shutdown(err_code);
    socket_.reset();
    BOOST_LOG_TRIVIAL(debug) << "Closed connection to " << remote_endpoint_;
  }

  std::shared_ptr<boost::asio::io_context> const io_ctx_;
  boost::asio::ssl::context ssl_ctx_;
  std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
      socket_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
};

/// @brief Strategy for receiving messages over TLS v1.3.
/// @details This class uses a TCP socket to receive messages of type MessageT
///          from a specified remote endpoint securely. Messages received are
///          processed by a callback function.
/// @tparam MessageT, the type of message to receive.
template <typename MessageT>
class Receiver : public simpleio::Receiver<MessageT>,
                 public std::enable_shared_from_this<Receiver<MessageT>> {
 public:
  /// @brief Construct from a shared io_context, Credentials struct, a local
  /// endpoint, and a callback function.
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, the local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  /// @param config, Credentials struct to use.
  /// @throw TransportException, if an error occurs while setting up the SSL
  /// context.
  Receiver(std::shared_ptr<boost::asio::io_context> const& io_ctx,
           boost::asio::ip::tcp::endpoint const& local_endpoint,
           typename simpleio::Receiver<MessageT>::callback_t message_cb,
           Credentials const& config)
      : acceptor_(*io_ctx, local_endpoint),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        strand_(boost::asio::make_strand(*io_ctx)),
        simpleio::Receiver<MessageT>(std::move(message_cb)) {
    try {
      ssl_ctx_.load_verify_file(config.ca_file.string());
      ssl_ctx_.use_certificate_chain_file(config.cert_file.string());
      ssl_ctx_.use_private_key_file(config.key_file.string(),
                                    boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream error_stream;
      error_stream << "Error setting up TLSv1.3 context: " << e.what();
      BOOST_LOG_TRIVIAL(error) << error_stream.str();
      throw std::runtime_error(error_stream.str());
    }
  }

  /// @brief Factory function to create a tls::Receiver.
  /// @details Constructs a receiver and starts accepting connections
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @param config, Credentials struct to use.
  /// @return A shared pointer to an initialized tls::Receiver.
  static std::shared_ptr<Receiver<MessageT>> create(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb,
      Credentials const& config) {
    auto receiver = std::make_shared<Receiver<MessageT>>(
        io_ctx, local_endpoint, std::move(message_cb), config);
    receiver->start_accepting();
    return receiver;
  }

  /// @brief Destructor
  ~Receiver() override {
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
    auto socket = std::make_shared<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
        acceptor_.get_executor(), ssl_ctx_);
    auto self = this->shared_from_this();
    acceptor_.async_accept(
        socket->lowest_layer(),
        boost::asio::bind_executor(
            strand_, [self, socket](boost::system::error_code err_code) {
              if (!err_code) {
                BOOST_LOG_TRIVIAL(info)
                    << "Accepted secure connection from "
                    << socket->lowest_layer().remote_endpoint();
                self->start_handshake(socket);
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "Accept failed: " << err_code.message();
              }
              self->start_accepting();  // Keep listening for new connections
            }));
  }

  /// @brief Start the TLS v1.3 handshake with the connected socket.
  /// @details This method performs the TLS handshake with the connected socket.
  ///          If the handshake is successful, it starts receiving messages from
  ///          the socket. If the handshake fails, it logs the error.
  /// @param socket, a shared pointer to the socket to perform the handshake on.
  void start_handshake(std::shared_ptr<boost::asio::ssl::stream<
                           boost::asio::ip::tcp::socket>> const& socket) {
    auto self = this->shared_from_this();
    socket->async_handshake(
        boost::asio::ssl::stream_base::server,
        boost::asio::bind_executor(
            strand_, [self, socket](boost::system::error_code err_code) {
              if (!err_code) {
                BOOST_LOG_TRIVIAL(debug) << "TLSv1.3 handshake successful!";
                self->start_receiving(socket);
              } else {
                BOOST_LOG_TRIVIAL(error)
                    << "TLSv1.3 handshake failed: " << err_code.message();
              }
            }));
  }

  /// @brief Start receiving messages from a socket provisioned to receive them.
  /// @details This method sets up an asynchronous read operation to receive
  ///          messages from the connected socket. When a message is received,
  ///          it calls the on_read method to process the message. If an error
  ///          occurs during receiving, it logs the error.
  /// @param socket, a shared pointer to the socket to receive messages from.
  void start_receiving(std::shared_ptr<boost::asio::ssl::stream<
                           boost::asio::ip::tcp::socket>> const& socket) {
    auto self = this->shared_from_this();
    auto buffer = std::make_shared<std::string>(MessageT::max_blob_size, '\0');

    boost::asio::async_read(
        *socket, boost::asio::buffer(*buffer),
        boost::asio::bind_executor(
            strand_, [self, buffer, socket](boost::system::error_code err_code,
                                            size_t bytes_recvd) {
              if (err_code == boost::asio::error::eof && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug)
                    << "Received " << bytes_recvd << " bytes securely.";
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
  boost::asio::ssl::context ssl_ctx_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
};

}  // namespace simpleio::transports::ip::tls
