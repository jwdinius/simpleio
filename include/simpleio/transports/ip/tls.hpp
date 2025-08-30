// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/log/trivial.hpp>
#include <deque>
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
                  Credentials const& config,
                  std::shared_ptr<simpleio::Framer> framer =
                      std::make_shared<simpleio::DefaultFramer>(),
                  bool streaming = false)
      : io_ctx_(std::move(io_ctx)),
        remote_endpoint_(std::move(remote_endpoint)),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        strand_(boost::asio::make_strand(*io_ctx_)),
        framer_(std::move(framer)) {
    try {
      ssl_ctx_.load_verify_file(config.ca_file.string());
      ssl_ctx_.use_certificate_chain_file(config.cert_file.string());
      ssl_ctx_.use_private_key_file(config.key_file.string(),
                                    boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream oss;
      oss << "Error setting up TLSv1.3 context: " << e.what();
      BOOST_LOG_TRIVIAL(error) << oss.str();
      throw TransportException(oss.str());
    }
    streaming_session_ = streaming
                             ? std::make_shared<StreamingSession>(
                                   io_ctx_, ssl_ctx_, remote_endpoint_, strand_)
                             : nullptr;
  }

  /// @brief Send a message.
  /// @details This method creates a new session for each message.
  ///          Sessions connect and send the message asynchronously.
  /// @param msg, the message to send.
  void send(MessageT const& msg) override {
    if (streaming_session_) {
      streaming_session_->enqueue(framer_->frame(msg.blob()));
      return;
    }
    auto session = std::make_shared<OneShotSession>(io_ctx_, ssl_ctx_, strand_,
                                                    remote_endpoint_,
                                                    framer_->frame(msg.blob()));
    session->start();
  }

 private:
  class OneShotSession : public std::enable_shared_from_this<OneShotSession> {
   public:
    OneShotSession(
        std::shared_ptr<boost::asio::io_context> const& io_ctx,
        boost::asio::ssl::context& ssl_ctx,
        boost::asio::strand<boost::asio::io_context::executor_type> strand,
        boost::asio::ip::tcp::endpoint endpoint, std::string blob)
        : socket_(*io_ctx, ssl_ctx),
          strand_(std::move(strand)),
          remote_endpoint_(std::move(endpoint)),
          blob_(std::move(blob)) {}

    void start() {
      auto self = this->shared_from_this();
      socket_.lowest_layer().async_connect(
          remote_endpoint_,
          boost::asio::bind_executor(
              strand_, [self](boost::system::error_code err_code) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TCP connect failed: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug)
                    << "TCP connected, starting TLS handshake";
                self->handshake();
              }));
    }

   private:
    void handshake() {
      auto self = this->shared_from_this();
      socket_.async_handshake(
          boost::asio::ssl::stream_base::client,
          boost::asio::bind_executor(
              strand_, [self](boost::system::error_code err_code) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TLS handshake failed: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug) << "TLS handshake succeeded";
                self->write();
              }));
    }

    void write() {
      auto self = this->shared_from_this();
      boost::asio::async_write(
          socket_, boost::asio::buffer(blob_.data(), blob_.size()),
          boost::asio::bind_executor(
              strand_,
              [self](boost::system::error_code err_code, std::size_t bytes) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TLS write failed: " << err_code.message();
                } else {
                  BOOST_LOG_TRIVIAL(debug)
                      << "Sent " << bytes << " bytes securely";
                }
                self->shutdown();
              }));
    }

    void shutdown() {
      auto self = this->shared_from_this();
      socket_.async_shutdown(boost::asio::bind_executor(
          strand_, [self](boost::system::error_code err_code) {
            if (err_code && err_code != boost::asio::error::eof) {
              BOOST_LOG_TRIVIAL(error)
                  << "TLS shutdown failed: " << err_code.message();
            } else {
              BOOST_LOG_TRIVIAL(debug) << "TLS shutdown completed";
            }
          }));
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    std::string blob_;
  };

  // ---------------------- Persistent streaming session ----------------------
  class StreamingSession
      : public std::enable_shared_from_this<StreamingSession> {
   public:
    StreamingSession(
        std::shared_ptr<boost::asio::io_context> const& io_ctx,
        boost::asio::ssl::context& ssl_ctx,
        boost::asio::ip::tcp::endpoint endpoint,
        boost::asio::strand<boost::asio::io_context::executor_type> strand)
        : socket_(*io_ctx, ssl_ctx),
          remote_endpoint_(std::move(endpoint)),
          strand_(std::move(strand)) {}

    ~StreamingSession() {
      close();
    }

    void enqueue(std::string blob) {
      auto self = this->shared_from_this();
      boost::asio::dispatch(
          strand_, [this, self, blob = std::move(blob)]() mutable {
            queue_.emplace_back(std::move(blob));
            if (!connected() && !connecting_) {
              return connect();
            }
            if (connected()) {
              return write();
            }
            BOOST_LOG_TRIVIAL(warning) << "enqueue fell through";
          });
    }

    bool connected() {
      return connected_ && socket_.lowest_layer().is_open();
    }

    void close() {
      auto self = this->shared_from_this();
      socket_.async_shutdown(boost::asio::bind_executor(
          strand_, [self](boost::system::error_code err_code) {
            if (err_code && err_code != boost::asio::error::eof) {
              BOOST_LOG_TRIVIAL(error)
                  << "TLS shutdown failed: " << err_code.message();
            } else {
              BOOST_LOG_TRIVIAL(debug) << "TLS shutdown completed";
            }
            self->connected_ = false;
            self->connecting_ = false;
          }));
    }

   private:
    void connect() {
      connecting_ = true;
      auto self = this->shared_from_this();
      socket_.lowest_layer().async_connect(
          remote_endpoint_,
          boost::asio::bind_executor(
              strand_, [this, self](boost::system::error_code err_code) {
                connecting_ = false;
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TCP stream connect failed: " << err_code.message();
                  // Leave queued data; next enqueue() will try again
                  return;
                }
                BOOST_LOG_TRIVIAL(debug) << "TCP stream starting handshake";
                self->handshake();
              }));
    }

    void handshake() {
      auto self = this->shared_from_this();
      socket_.async_handshake(
          boost::asio::ssl::stream_base::client,
          boost::asio::bind_executor(
              strand_, [self](boost::system::error_code err_code) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TLS handshake failed: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug) << "TLS handshake succeeded";
                self->connected_ = true;
                if (!self->queue_.empty()) {
                  self->write();
                }
              }));
    }

    void write() {
      if (queue_.empty() || !connected()) {
        return;
      }
      auto self = this->shared_from_this();

      // coalesce front message into a buffer; if you want to write multiple
      // frames at once, you could gather-write here. For simplicity, one frame
      // at a time:
      auto current = std::move(queue_.front());
      queue_.pop_front();

      boost::asio::async_write(
          socket_, boost::asio::buffer(current),
          boost::asio::bind_executor(
              strand_,
              [this, self](boost::system::error_code err_code, std::size_t n) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TLS stream write failed: " << err_code.message();
                  // Close the socket; queued messages remain. Next enqueue will
                  // reconnect.
                  close();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug) << "TLS stream sent " << n
                                         << " bytes to " << remote_endpoint_;
                if (!queue_.empty()) {
                  write();
                }
              }));
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    std::deque<std::string> queue_;
    bool connected_{false};
    bool connecting_{false};
  };

  std::shared_ptr<boost::asio::io_context> const io_ctx_;
  boost::asio::ssl::context ssl_ctx_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::shared_ptr<StreamingSession> streaming_session_;
  std::shared_ptr<simpleio::Framer> framer_;
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
  ///                    received.
  /// @param config, Credentials struct to use.
  /// @param framer, the framing strategy to use for incoming messages.
  /// @throw TransportException, if an error occurs while setting up the SSL
  /// context.
  Receiver(std::shared_ptr<boost::asio::io_context> const& io_ctx,
           boost::asio::ip::tcp::endpoint const& local_endpoint,
           typename simpleio::Receiver<MessageT>::callback_t message_cb,
           Credentials const& config, std::shared_ptr<simpleio::Framer> framer)
      : acceptor_(*io_ctx, local_endpoint),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        strand_(boost::asio::make_strand(*io_ctx)),
        simpleio::Receiver<MessageT>(std::move(message_cb)),
        framer_(std::move(framer)) {
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
  /// @param framer, the framing strategy to use for incoming messages (default:
  /// DefaultFramer)
  /// @return A shared pointer to an initialized tls::Receiver.
  static std::shared_ptr<Receiver<MessageT>> create(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb,
      Credentials const& config,
      std::shared_ptr<simpleio::Framer> framer =
          std::make_shared<simpleio::DefaultFramer>()) {
    auto receiver = std::make_shared<Receiver<MessageT>>(
        io_ctx, local_endpoint, std::move(message_cb), config,
        std::move(framer));
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
    auto buffer = std::make_shared<std::string>();
    buffer->reserve(MessageT::max_blob_size);
    auto read_buffer =
        std::make_shared<std::string>(MessageT::max_blob_size, '\0');

    auto do_read = std::make_shared<std::function<void()>>();
    *do_read = [this, self, socket, buffer, read_buffer, do_read]() -> void {
      socket->async_read_some(
          boost::asio::buffer(*read_buffer),
          boost::asio::bind_executor(
              strand_,
              [this, self, socket, buffer, read_buffer, do_read](
                  boost::system::error_code err_code, std::size_t bytes_recvd) {
                if (err_code && err_code != boost::asio::error::eof) {
                  BOOST_LOG_TRIVIAL(error)
                      << "TLS read failed: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug)
                    << "TLS received " << bytes_recvd << " bytes.";
                buffer->append(read_buffer->data(), bytes_recvd);
                std::string msg;
                while (framer_->try_unframe(*buffer, msg)) {
                  self->on_read(MessageT(msg));
                }
                (*do_read)();  // recurse
              }));
    };

    boost::asio::dispatch(strand_, [do_read]() { (*do_read)(); });
  }

  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::ssl::context ssl_ctx_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::shared_ptr<simpleio::Framer> framer_;
};

}  // namespace simpleio::transports::ip::tls
