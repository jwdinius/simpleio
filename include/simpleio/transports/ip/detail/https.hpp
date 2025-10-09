// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/version.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/detail/http.hpp"
#include "simpleio/transports/ip/detail/tls.hpp"
#include "simpleio/transports/ip/typedefs.hpp"

namespace simpleio::transports::ip::https {

/// @brief HTTPS client for sending requests and receiving responses
/// asynchronously.
/// @details This class uses Boost Beast to securely send HTTP requests and
/// receive
///          HTTP responses of a templated service type using TLS v1.3.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class Client : public simpleio::Client<ServiceT>,
               public std::enable_shared_from_this<Client<ServiceT>> {
 public:
  /// @brief Constructor that initializes the HTTPS client with a shared
  /// io_context,
  ///          a TLS configuration, a remote endpoint, and a timeout
  ///          duration.
  /// @param ioc, the shared io_context to use for asynchronous operations.
  /// @param remote_endpoint, the remote endpoint to connect to.
  /// @param timeout, the timeout duration for operations.
  /// @param config, TlsCredentials to use for secure connections.
  explicit Client(std::shared_ptr<boost::asio::io_context> ioc,
                  boost::asio::ip::tcp::endpoint remote_endpoint,
                  std::chrono::duration<int> timeout,
                  TlsCredentials const& config)
      : io_ctx_(std::move(ioc)),
        remote_endpoint_(std::move(remote_endpoint)),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        stream_(*io_ctx_, ssl_ctx_),
        timeout_(timeout),
        simpleio::Client<ServiceT>() {
    try {
      ssl_ctx_.load_verify_file(config.ca_file.string());
      ssl_ctx_.use_certificate_chain_file(config.cert_file.string());
      ssl_ctx_.use_private_key_file(config.key_file.string(),
                                    boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream err;
      err << "TLSv1.3 setup failed: " << e.what();
      BOOST_LOG_TRIVIAL(error) << err.str();
      throw TransportException(err.str());
    }
  }

  /// @brief Asynchronously sends a secure request and returns a future for the
  /// response.
  /// @details This function securely sends an HTTP request and returns a future
  /// that will
  ///          hold the response once it is received. The request is sent using
  ///          Boost Beast's asynchronous operations.
  /// @param req, the request to send, which is of type ServiceT::RequestT.
  /// @return std::future<typename ServiceT::ResponseT>, a future that will hold
  ///          the response once it is received.
  std::future<typename ServiceT::ResponseT> send_request_async(
      typename ServiceT::RequestT const& req) override {
    auto self = this->shared_from_this();
    self->req_ = req.entity();
    self->promise_ =
        std::make_shared<std::promise<typename ServiceT::ResponseT>>();
    self->connect();
    return promise_->get_future();
  }

  /// @brief Synchronously sends a secure request and returns a response.
  /// @param req, the request to send, which is of type ServiceT::RequestT.
  /// @return typename ServiceT::ResponseT, the response.
  typename ServiceT::ResponseT send_request(
      typename ServiceT::RequestT const& req) override {
    auto self = this->shared_from_this();
    auto future = self->send_request_async(req);
    // Wait for the future to complete and return the response
    if (!future.valid()) {
      throw TransportException(
          "Failed to get a valid response from the https::Client.");
    }
    return future.get();
  }

 private:
  /// @brief Connects to the remote endpoint.
  void connect() {
    auto self = this->shared_from_this();
    BOOST_LOG_TRIVIAL(debug) << "https::Client connecting. (1/3)";
    // Reset the stream
    self->stream_ = boost::beast::ssl_stream<boost::beast::tcp_stream>(
        *(self->io_ctx_), self->ssl_ctx_);
    BOOST_LOG_TRIVIAL(debug) << "https::Client connecting. (2/3)";
    self->stream_.next_layer().expires_after(self->timeout_);
    BOOST_LOG_TRIVIAL(debug) << "https::Client connecting. (3/3)";
    self->stream_.next_layer().async_connect(
        self->remote_endpoint_, boost::beast::bind_front_handler(
                                    &Client<ServiceT>::start_handshake, self));
    BOOST_LOG_TRIVIAL(debug) << "https::Client dispatched.";
  }

  /// @brief Starts the TLS handshake after a successful connection.
  void start_handshake(boost::beast::error_code err_code) {
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "Connection failed.");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::Client connected, starting TLS handshake.";

    // Set a timeout on the operation
    self->stream_.next_layer().expires_after(self->timeout_);

    // Perform the TLS handshake
    self->stream_.async_handshake(boost::asio::ssl::stream_base::client,
                                  boost::beast::bind_front_handler(
                                      &Client<ServiceT>::write_request, self));
  }

  /// @brief Writes the request to the remote endpoint after a successful
  /// handshake.
  void write_request(boost::beast::error_code err_code) {
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "Connection failed.");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::Client handshake completed, sending request.";

    // Set a timeout on the operation
    self->stream_.next_layer().expires_after(self->timeout_);

    // Send the HTTP request to the remote host
    boost::beast::http::async_write(
        self->stream_, self->req_,
        boost::beast::bind_front_handler(&Client<ServiceT>::await_response,
                                         self));
  }

  /// @brief Awaits the response after sending the request.
  void await_response(boost::beast::error_code err_code,
                      std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "Failed to send request.");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::Client sent request, awaiting response.";

    // Receive the HTTP response
    boost::beast::http::async_read(
        self->stream_, self->buffer_, self->res_,
        boost::beast::bind_front_handler(&Client<ServiceT>::handle_response,
                                         self));
  }

  /// @brief Handles the response received from the remote endpoint after it has
  /// been read.
  /// @details This function will close the connection gracefully after handling
  /// the response.
  void handle_response(boost::beast::error_code err_code,
                       std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "Failed to read response.");
    }
    BOOST_LOG_TRIVIAL(debug) << "https::Client received response.";

    self->promise_->set_value(
        typename ServiceT::ResponseT(std::move(self->res_)));

    self->stream_.async_shutdown(
        [self](boost::beast::error_code err_code) mutable {
          BOOST_LOG_TRIVIAL(debug)
              << "https::Client handled response, closing connection.";
          if (err_code && err_code != boost::asio::error::eof) {
            BOOST_LOG_TRIVIAL(error)
                << "https::Client TLS shutdown failed: " << err_code.message();
          }
        });
    // If we get here then the connection is closed gracefully
  }

  std::shared_ptr<boost::asio::io_context> io_ctx_;
  boost::asio::ssl::context ssl_ctx_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  std::chrono::duration<int> timeout_;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  typename ServiceT::RequestT::entity_t req_;
  std::shared_ptr<std::promise<typename ServiceT::ResponseT>> promise_;
  typename ServiceT::ResponseT::entity_t res_;
};

/// @brief  HTTP server session for handling incoming requests and sending
/// responses
///         securely.
/// @details Each request is handled securely in its own session, allowing for
/// concurrent
///          processing of multiple requests. This class is inspired by the
///          Boost Beast Github example for async HTTP servers.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class ServerSession
    : public std::enable_shared_from_this<ServerSession<ServiceT>> {
 public:
  /// @brief Constructor that initializes the asynchronous HTTP server session
  /// with a request
  ///          callback, a timeout duration, a TCP socket, and an SSL
  ///          context.
  /// @param request_cb, the callback function to handle incoming requests.
  /// @param timeout, the timeout duration for operations.
  /// @param socket, the socket to use for the session.
  /// @param ssl_ctx, the shared pointer to the SSL context for secure
  /// connections.
  explicit ServerSession(
      typename Server<ServiceT>::request_callback_t request_cb,
      std::chrono::duration<int> timeout, boost::asio::ip::tcp::socket&& socket,
      std::shared_ptr<boost::asio::ssl::context> const& ssl_ctx)
      : request_cb_(request_cb),
        timeout_(timeout),
        stream_(std::move(socket), *ssl_ctx) {}

  ~ServerSession() {
    BOOST_LOG_TRIVIAL(debug) << "https::ServerSession destroyed.";
  }

  /// @brief Starts the session by initiating the TLS handshake.
  void run() {
    auto self = this->shared_from_this();
    self->stream_.async_handshake(
        boost::asio::ssl::stream_base::server,
        boost::beast::bind_front_handler(
            &ServerSession<ServiceT>::await_request, self));
  }

  void set_close_handler(
      std::function<void(std::shared_ptr<ServerSession<ServiceT>>)> cb) {
    on_close_ = std::move(cb);
  }

 private:
  /// @brief Awaits an incoming request from the client the TLS handshake.
  void await_request(boost::beast::error_code err_code) {
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "handshake");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::ServerSession running, awaiting request.";
    self->req_ = {};
    self->stream_.next_layer().expires_after(self->timeout_);
    boost::beast::http::async_read(
        self->stream_, self->buffer_, self->req_,
        boost::beast::bind_front_handler(
            &ServerSession<ServiceT>::handle_request, self));
  }

  /// @brief Handles the incoming request after it has been read.
  void handle_request(boost::beast::error_code err_code,
                      std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    auto self = this->shared_from_this();
    if (err_code == boost::beast::http::error::end_of_stream) {
      return self->close();
    }
    if (err_code) {
      return http::fail(err_code, "read");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::ServerSession received request and is handling it.";

    boost::asio::dispatch(self->stream_.get_executor(), [self]() mutable {
      self->res_ =
          self->request_cb_(typename ServiceT::RequestT(self->req_)).entity();
      BOOST_LOG_TRIVIAL(debug)
          << "Callback returned response entity: " << self->res_;
      bool should_close = !(self->res_.keep_alive());
      boost::beast::http::async_write(
          self->stream_, self->res_,
          boost::beast::bind_front_handler(&ServerSession<ServiceT>::teardown,
                                           self, should_close));
    });
  }

  /// @brief Teardown the session after the response has been sent.
  void teardown(bool should_close, boost::beast::error_code err_code,
                std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return http::fail(err_code, "write");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "https::ServerSession handled request and sent response.";

    if (should_close) {
      return close();
    }

    await_request(err_code);
  }

  /// @brief Closes the session gracefully after handling the request.
  void close() {
    auto self = this->shared_from_this();
    self->stream_.async_shutdown(
        [self](boost::beast::error_code err_code) mutable {
          BOOST_LOG_TRIVIAL(debug)
              << "https::ServerSession closing connection.";
          if (err_code && err_code != boost::asio::error::eof) {
            BOOST_LOG_TRIVIAL(error)
                << "https::ServerSession TLS shutdown failed: "
                << err_code.message();
          }
          if (self->on_close_) {
            self->on_close_(self);
          }
        });
  }

  typename simpleio::Server<ServiceT>::request_callback_t request_cb_;
  std::chrono::duration<int> timeout_;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  typename ServiceT::RequestT::entity_t req_;
  typename ServiceT::ResponseT::entity_t res_;
  std::function<void(std::shared_ptr<ServerSession<ServiceT>>)> on_close_;
};

/// @brief Server class for accepting incoming HTTP connections and
/// handling requests
///        securely.
/// @details This class uses Boost Beast to accept incoming HTTP connections and
///          handle requests using a templated service type. It is designed to
///          run asynchronously and can handle multiple connections
///          concurrently.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class Server : public simpleio::Server<ServiceT>,
               public std::enable_shared_from_this<Server<ServiceT>> {
 public:
  /// @brief Constructor that initializes the HTTPS server with a shared
  /// io_context,
  ///        a TLS configuration, a local endpoint, a request callback, a
  ///        worker, and a timeout duration.
  /// @param ioc, the shared io_context to use for asynchronous operations.
  /// @param local_endpoint, the local endpoint to bind the server to.
  /// @param request_cb, the callback function to handle incoming requests.
  /// @param timeout, the timeout duration for operations.
  /// @param config, TlsCredentials to use for secure connections.
  Server(
      std::shared_ptr<boost::asio::io_context> ioc,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      std::function<typename ServiceT::ResponseT(typename ServiceT::RequestT)>
          request_cb,
      std::chrono::duration<int> timeout, TlsCredentials const& config)
      : ioc_(std::move(ioc)),
        ssl_ctx_(std::make_shared<boost::asio::ssl::context>(
            boost::asio::ssl::context::tlsv13)),
        acceptor_(*ioc_),
        timeout_(timeout),
        strand_(boost::asio::make_strand(*ioc_)),
        simpleio::Server<ServiceT>(std::move(request_cb)) {
    try {
      ssl_ctx_->load_verify_file(config.ca_file.string());
      ssl_ctx_->use_certificate_chain_file(config.cert_file.string());
      ssl_ctx_->use_private_key_file(config.key_file.string(),
                                     boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream error_stream;
      error_stream << "Error setting up TLSv1.3 context: " << e.what();
      BOOST_LOG_TRIVIAL(error) << error_stream.str();
      throw std::runtime_error(error_stream.str());
    }
    boost::beast::error_code err_code;
    acceptor_.open(local_endpoint.protocol(), err_code);

    if (err_code) {
      throw TransportException("open");
    }

    acceptor_.set_option(boost::asio::socket_base::reuse_address(true),
                         err_code);
    if (err_code) {
      throw TransportException("set_option");
    }

    acceptor_.bind(local_endpoint, err_code);
    if (err_code) {
      BOOST_LOG_TRIVIAL(error) << "bind failed: " << err_code.message();
      throw TransportException("bind");
    }

    acceptor_.listen(boost::asio::socket_base::max_listen_connections,
                     err_code);
    if (err_code) {
      throw TransportException("listen");
    }
  }

  /// @brief Factory function that creates a fully initialized HTTPS server with
  /// a shared io_context,
  ///          a local endpoint, a request callback, a timeout
  ///          duration, and TLS credentials
  /// @param ioc, the shared io_context to use for asynchronous operations.
  /// @param local_endpoint, the local endpoint to bind the server to.
  /// @param request_cb, the callback function to handle incoming requests.
  /// @param timeout, the timeout duration for operations.
  /// @param config, TlsCredentials to use for secure connections.
  /// @return shared pointer to the created https::Server
  static std::shared_ptr<Server<ServiceT>> create(
      std::shared_ptr<boost::asio::io_context> ioc,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      std::function<typename ServiceT::ResponseT(typename ServiceT::RequestT)>
          request_cb,
      std::chrono::duration<int> timeout, TlsCredentials config) {
    auto server = std::make_shared<Server<ServiceT>>(
        ioc, local_endpoint, std::move(request_cb), timeout, config);
    server->start();
    return server;
  }

  /// @brief Destructor that closes the acceptor and logs the shutdown.
  /// @details This destructor ensures that the acceptor is closed gracefully
  ///          when the https::Server object is destroyed, preventing any
  ///          further incoming connections.
  ~Server() {
    BOOST_LOG_TRIVIAL(debug) << "https::Server shutting down.";
    boost::beast::error_code err_code;
    acceptor_.cancel(err_code);
    acceptor_.close(err_code);
    if (err_code) {
      BOOST_LOG_TRIVIAL(error)
          << "https::Server failed to close acceptor: " << err_code.message();
    }

    while (!sessions_.empty()) {
      auto it = sessions_.begin();
      auto s = *it;
      sessions_.erase(it);
    }
  }

  /// @brief Starts the HTTPS server and begins accepting incoming connections.
  void start() {
    BOOST_LOG_TRIVIAL(debug) << "https::Server starting.";
    start_accepting();
  }

 private:
  /// @brief Starts accepting incoming connections asynchronously.
  void start_accepting() {
    auto self = this->shared_from_this();
    BOOST_LOG_TRIVIAL(debug)
        << "https::Server started, start accepting connections.";
    self->acceptor_.async_accept(boost::asio::bind_executor(
        self->strand_,
        boost::beast::bind_front_handler(&Server<ServiceT>::accept, self)));
  }

  /// @brief Start the HTTPS Server session after connecting the socket.
  void accept(boost::beast::error_code err_code,
              boost::asio::ip::tcp::socket socket) {
    auto self = this->shared_from_this();
    if (err_code) {
      return http::fail(err_code, "accept");
    }
    BOOST_LOG_TRIVIAL(debug) << "https::Server accepted a connection.";
    auto session = std::make_shared<ServerSession<ServiceT>>(
        self->request_cb_, self->timeout_, std::move(socket), self->ssl_ctx_);
    session->set_close_handler([weak = std::weak_ptr{self}](
                                   std::shared_ptr<ServerSession<ServiceT>> s) {
      if (auto owner = weak.lock()) {
        boost::asio::dispatch(owner->strand_,
                              [owner, s] { owner->sessions_.erase(s); });
      }
    });
    self->sessions_.insert(session);
    session->run();
    self->start_accepting();
  }

  std::shared_ptr<boost::asio::io_context> ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx_;
  std::chrono::duration<int> timeout_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  std::unordered_set<std::shared_ptr<ServerSession<ServiceT>>> sessions_;
};
}  // namespace simpleio::transports::ip::https
