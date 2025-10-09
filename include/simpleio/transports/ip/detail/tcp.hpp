// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/log/trivial.hpp>
#include <deque>
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
  /// @param framer, the framing strategy to use (default: DefaultFramer)
  /// @param streaming, whether to enable streaming mode (default: false)
  explicit Sender(std::shared_ptr<boost::asio::io_context> const& io_ctx,
                  boost::asio::ip::tcp::endpoint remote_endpoint,
                  std::shared_ptr<simpleio::Framer> framer =
                      std::make_shared<simpleio::DefaultFramer>(),
                  bool streaming = false)
      : io_ctx_(io_ctx),
        remote_endpoint_(std::move(remote_endpoint)),
        strand_(boost::asio::make_strand(*io_ctx)),
        streaming_session_(streaming ? std::make_shared<StreamingSession>(
                                           io_ctx_, remote_endpoint_, strand_)
                                     : nullptr),
        framer_(std::move(framer)) {}

  /// @brief Send a message.
  /// @details This method creates a new session for each message.
  ///          Sessions connect and send the message asynchronously.
  /// @param msg, the message to send.
  void send(MessageT const& msg) override {
    if (streaming_session_) {
      streaming_session_->enqueue(framer_->frame(msg.blob()));
      return;
    }
    auto session = std::make_shared<OneShotSession>(
        io_ctx_, remote_endpoint_, strand_, framer_->frame(msg.blob()));
    session->start();
  }

 private:
  class OneShotSession : public std::enable_shared_from_this<OneShotSession> {
   public:
    OneShotSession(
        std::shared_ptr<boost::asio::io_context> const& io_ctx,
        boost::asio::ip::tcp::endpoint endpoint,
        boost::asio::strand<boost::asio::io_context::executor_type> strand,
        std::string blob)
        : socket_(*io_ctx),
          remote_endpoint_(std::move(endpoint)),
          strand_(std::move(strand)),
          blob_(std::move(blob)) {}

    void start() {
      auto self = this->shared_from_this();
      socket_.async_connect(
          self->remote_endpoint_,
          boost::asio::bind_executor(
              self->strand_, [self](boost::system::error_code err_code) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "Failed to connect: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug)
                    << "Connected to " << self->remote_endpoint_;
                self->write();
              }));
    }

   private:
    void write() {
      auto self = this->shared_from_this();
      boost::asio::async_write(
          self->socket_, boost::asio::buffer(blob_.data(), blob_.size()),
          boost::asio::bind_executor(
              self->strand_, [self](boost::system::error_code err_code,
                                    std::size_t bytes_sent) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "Write failed: " << err_code.message();
                } else {
                  BOOST_LOG_TRIVIAL(debug)
                      << "Sent " << bytes_sent << " bytes to "
                      << self->remote_endpoint_;
                }
                boost::system::error_code ignored_ec;
                self->socket_.shutdown(
                    boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
                self->socket_.close(ignored_ec);
              }));
    }

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::string const blob_;
  };

  // ---------------------- Persistent streaming session ----------------------
  class StreamingSession
      : public std::enable_shared_from_this<StreamingSession> {
   public:
    StreamingSession(
        std::shared_ptr<boost::asio::io_context> const& io_ctx,
        boost::asio::ip::tcp::endpoint endpoint,
        boost::asio::strand<boost::asio::io_context::executor_type> strand)
        : socket_(*io_ctx),
          remote_endpoint_(std::move(endpoint)),
          strand_(std::move(strand)) {}

    ~StreamingSession() {
      close();
    }

    void enqueue(std::string blob) {
      auto self = this->shared_from_this();
      boost::asio::dispatch(
          self->strand_, [self, blob = std::move(blob)]() mutable {
            self->queue_.emplace_back(std::move(blob));
            if (!self->connected() && !self->connecting_) {
              return self->connect();
            }
            if (self->connected()) {
              return self->write();
            }
            BOOST_LOG_TRIVIAL(warning) << "enqueue fell through";
          });
    }

    bool connected() {
      return connected_ && socket_.is_open();
    }

    void close() {
      boost::asio::dispatch(strand_, [this]() {
        boost::system::error_code err_code;
        if (socket_.is_open()) {
          socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                           err_code);
          socket_.close(err_code);
        }
        connected_ = false;
        connecting_ = false;
      });
    }

   private:
    void connect() {
      connecting_ = true;
      auto self = this->shared_from_this();
      self->socket_.async_connect(
          self->remote_endpoint_,
          boost::asio::bind_executor(
              self->strand_, [self](boost::system::error_code err_code) {
                self->connecting_ = false;
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "stream connect failed: " << err_code.message();
                  // Leave queued data; next enqueue() will try again
                  return;
                }
                self->connected_ = true;
                BOOST_LOG_TRIVIAL(debug)
                    << "stream connected to " << self->remote_endpoint_;
                if (!self->queue_.empty()) {
                  self->write();
                }
              }));
    }

    void write() {
      auto self = this->shared_from_this();
      if (self->queue_.empty() || !self->connected()) {
        return;
      }

      // coalesce front message into a buffer; if you want to write multiple
      // frames at once, you could gather-write here. For simplicity, one frame
      // at a time:
      auto current = std::move(self->queue_.front());
      self->queue_.pop_front();

      boost::asio::async_write(
          self->socket_, boost::asio::buffer(current),
          boost::asio::bind_executor(
              self->strand_,
              [self](boost::system::error_code err_code, std::size_t n) {
                if (err_code) {
                  BOOST_LOG_TRIVIAL(error)
                      << "stream write failed: " << err_code.message();
                  // Close the socket; queued messages remain. Next enqueue will
                  // reconnect.
                  boost::system::error_code ignore;
                  self->socket_.shutdown(
                      boost::asio::ip::tcp::socket::shutdown_both, ignore);
                  self->socket_.close(ignore);
                  self->connected_ = false;
                  return;
                }
                BOOST_LOG_TRIVIAL(debug) << "stream sent " << n << " bytes to "
                                         << self->remote_endpoint_;
                if (!self->queue_.empty()) {
                  self->write();
                }
              }));
    }

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;

    std::deque<std::string> queue_;
    bool connected_{false};
    bool connecting_{false};
  };

  std::shared_ptr<boost::asio::io_context> io_ctx_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::shared_ptr<StreamingSession> streaming_session_;
  std::shared_ptr<simpleio::Framer> framer_;
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
  ///                    received.
  /// @param framer, the framing strategy to use for incoming messages (default:
  /// DefaultFramer)
  explicit Receiver(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename simpleio::Receiver<MessageT>::callback_t message_cb,
      std::shared_ptr<simpleio::Framer> framer)
      : acceptor_(*io_ctx, local_endpoint),
        strand_(boost::asio::make_strand(*io_ctx)),
        simpleio::Receiver<MessageT>(std::move(message_cb)),
        framer_(std::move(framer)) {}

  /// @brief Factory function to create a tcp::Receiver.
  /// @details Constructs a receiver and starts accepting connections
  /// @param io_ctx, the shared io_context.
  /// @param local_endpoint, local endpoint to listen on.
  /// @param message_cb, the callback function to call when a message is
  /// received.
  /// @param framer, the framing strategy to use for incoming messages (default:
  /// DefaultFramer)
  /// @return A shared pointer to an initialized tcp::Receiver.
  static std::shared_ptr<Receiver<MessageT>> create(
      std::shared_ptr<boost::asio::io_context> const& io_ctx,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      typename Receiver<MessageT>::callback_t message_cb,
      std::shared_ptr<simpleio::Framer> framer =
          std::make_shared<simpleio::DefaultFramer>()) {
    auto receiver = std::make_shared<Receiver<MessageT>>(
        io_ctx, local_endpoint, std::move(message_cb), std::move(framer));
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
                      << "Read failed: " << err_code.message();
                  return;
                }
                BOOST_LOG_TRIVIAL(debug)
                    << "Received " << bytes_recvd << " bytes.";
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
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::shared_ptr<simpleio::Framer> framer_;
};

}  // namespace simpleio::transports::ip::tcp
