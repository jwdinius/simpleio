// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

/// @brief Logs an error message with the provided error code and description.
/// @details This function is shared between HTTP and HTTPS clients and servers.
/// @param err_code, the error code to log.
/// @param what, a description of the error to log.
inline void fail(boost::beast::error_code err_code, char const* what) {
  BOOST_LOG_TRIVIAL(error) << what << ": " << err_code.message();
}

/// @brief HTTP client for sending requests and receiving responses
/// asynchronously.
/// @details This class uses Boost Beast to send HTTP requests and receive
///          HTTP responses of a templated service type. This class is inspired
///          by the Boost Beast Github example for async HTTP clients.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class HttpClient : public std::enable_shared_from_this<HttpClient<ServiceT>>,
                   public Client<ServiceT> {
 public:
  /// @brief Constructor that initializes the HTTP client with a shared
  /// io_context,
  ///          a remote endpoint, a worker, and a timeout duration.
  /// @param ioc, the shared io_context to use for asynchronous operations.
  /// @param remote_endpoint, the remote endpoint to connect to.
  /// @param worker, the shared worker.
  /// @param timeout, the timeout duration for operations.
  explicit HttpClient(std::shared_ptr<boost::asio::io_context> const& ioc,
                      boost::asio::ip::tcp::endpoint remote_endpoint,
                      std::shared_ptr<simpleio::Worker> const& worker,
                      std::chrono::duration<int> timeout)
      : io_ctx_(ioc),
        remote_endpoint_(std::move(remote_endpoint)),
        stream_(*ioc),
        timeout_(timeout),
        Client<ServiceT>(worker) {}

  /// @brief Asynchronously sends a request and returns a future for the
  /// response.
  /// @details This function sends an HTTP request and returns a future that
  /// will
  ///          hold the response once it is received. The request is sent using
  ///          Boost Beast's asynchronous operations.
  /// @param req, the request to send, which is of type ServiceT::RequestT.
  /// @return std::future<typename ServiceT::ResponseT>, a future that will hold
  ///          the response once it is received.
  std::future<typename ServiceT::ResponseT> send_request_async(
      typename ServiceT::RequestT const& req) override {
    req_ = req.entity();
    promise_ = std::make_shared<std::promise<typename ServiceT::ResponseT>>();
    connect();
    return promise_->get_future();
  }

  /// @brief Synchronously sends a request and returns a response.
  /// @param req, the request to send, which is of type ServiceT::RequestT.
  /// @return typename ServiceT::ResponseT, the response.
  typename ServiceT::ResponseT send_request(
      typename ServiceT::RequestT const& req) override {
    auto future = send_request_async(req);
    // Wait for the future to complete and return the response
    if (!future.valid()) {
      throw TransportException(
          "Failed to get a valid response from the HttpClient.");
    }
    return future.get();
  }

 private:
  /// @brief Connects to the remote endpoint and starts the asynchronous
  /// request.
  void connect() {
    BOOST_LOG_TRIVIAL(debug) << "HttpClient connecting.";

    stream_.expires_after(timeout_);
    stream_.async_connect(
        remote_endpoint_,
        boost::beast::bind_front_handler(&HttpClient<ServiceT>::write_request,
                                         this->shared_from_this()));
  }

  /// @brief Writes the request to the remote endpoint after a successful
  /// connection.
  void write_request(boost::beast::error_code err_code) {
    if (err_code) {
      return fail(err_code, "Connection failed.");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpClient connected, sending request.";

    // Set a timeout on the operation
    stream_.expires_after(timeout_);

    // Send the HTTP request to the remote host
    boost::beast::http::async_write(
        stream_, req_,
        boost::beast::bind_front_handler(&HttpClient<ServiceT>::await_response,
                                         this->shared_from_this()));
  }

  /// @brief Awaits the response after sending the request.
  void await_response(boost::beast::error_code err_code,
                      std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "Failed to send request.");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpClient sent request, awaiting response.";

    // Receive the HTTP response
    boost::beast::http::async_read(
        stream_, buffer_, res_,
        boost::beast::bind_front_handler(&HttpClient<ServiceT>::handle_response,
                                         this->shared_from_this()));
  }

  /// @brief Handles the response received from the remote endpoint after it has
  /// been read.
  /// @details This function will close the connection gracefully after handling
  /// the response.
  void handle_response(boost::beast::error_code err_code,
                       std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "Failed to read response.");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpClient received response.";

    promise_->set_value(typename ServiceT::ResponseT(std::move(res_)));

    // Gracefully close the socket
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                              err_code);
    stream_.socket().close();

    // not_connected happens sometimes so don't bother reporting it.
    if (err_code && err_code != boost::beast::errc::not_connected) {
      return fail(err_code, "Failed to close connection.");
    }

    // If we get here then the connection is closed gracefully
    BOOST_LOG_TRIVIAL(debug) << "HttpClient closed connection.";
  }

  std::shared_ptr<boost::asio::io_context> io_ctx_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  std::chrono::duration<int> timeout_;
  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  typename ServiceT::RequestT::entity_t req_;
  std::shared_ptr<std::promise<typename ServiceT::ResponseT>> promise_;
  typename ServiceT::ResponseT::entity_t res_;
};

/// @brief  HTTP server session for handling incoming requests and sending
/// responses.
/// @details Each request is handled in its own session, allowing for concurrent
///          processing of multiple requests. This class is inspired by the
///          Boost Beast Github example for async HTTP servers.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class HttpServerSession
    : public std::enable_shared_from_this<HttpServerSession<ServiceT>> {
 public:
  /// @brief Constructor that initializes the asynchronous HTTP server session
  /// with a request
  ///          callback, a worker, a timeout duration, and a socket.
  /// @param request_cb, the callback function to handle incoming requests.
  /// @param worker, the shared worker to process requests.
  /// @param timeout, the timeout duration for operations.
  /// @param socket, the socket to use for the session.
  explicit HttpServerSession(
      typename Server<ServiceT>::request_callback_t request_cb,
      std::shared_ptr<Worker> worker, std::chrono::duration<int> timeout,
      boost::asio::ip::tcp::socket&& socket)
      : request_cb_(request_cb),
        worker_(std::move(worker)),
        timeout_(timeout),
        stream_(std::move(socket)) {}

  /// @brief Starts the session by awaiting the request.
  void run() {
    boost::asio::dispatch(stream_.get_executor(),
                          boost::beast::bind_front_handler(
                              &HttpServerSession<ServiceT>::await_request,
                              this->shared_from_this()));
  }

 private:
  /// @brief Awaits an incoming request from the client after session is
  /// started.
  void await_request() {
    BOOST_LOG_TRIVIAL(debug) << "HttpServerSession running, awaiting request.";
    req_ = {};
    stream_.expires_after(timeout_);
    boost::beast::http::async_read(
        stream_, buffer_, req_,
        boost::beast::bind_front_handler(
            &HttpServerSession<ServiceT>::handle_request,
            this->shared_from_this()));
  }

  /// @brief Handles the incoming request after it has been read.
  void handle_request(boost::beast::error_code err_code,
                      std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code == boost::beast::http::error::end_of_stream) {
      return close();
    }
    if (err_code) {
      return fail(err_code, "read");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "HttpServerSession received request and is handling it.";

    auto self = this->shared_from_this();
    this->worker_->push([self] {
      self->res_ =
          self->request_cb_(typename ServiceT::RequestT(self->req_)).entity();
      boost::asio::dispatch(self->stream_.get_executor(), [self]() mutable {
        BOOST_LOG_TRIVIAL(debug)
            << "Callback returned response entity: " << self->res_;
        bool keep_alive = self->res_.keep_alive();
        boost::beast::http::async_write(
            self->stream_, std::move(self->res_),
            boost::beast::bind_front_handler(
                &HttpServerSession<ServiceT>::teardown, self, keep_alive));
      });
    });
  }

  /// @brief Teardown the session after the response has been sent.
  void teardown(bool _close, boost::beast::error_code err_code,
                std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "write");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "HttpServerSession handled request and sent response.";

    if (_close) {
      return close();
    }

    await_request();
  }

  /// @brief Closes the session gracefully after handling the request.
  void close() {
    BOOST_LOG_TRIVIAL(debug) << "HttpServerSession closing connection.";
    boost::beast::error_code err_code;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send,
                              err_code);
  }

  typename Server<ServiceT>::request_callback_t request_cb_;
  std::shared_ptr<Worker> worker_;
  std::chrono::duration<int> timeout_;
  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  typename ServiceT::RequestT::entity_t req_;
  typename ServiceT::ResponseT::entity_t res_;
};

/// @brief HttpServer class for accepting incoming HTTP connections and handling
/// requests.
/// @details This class uses Boost Beast to accept incoming HTTP connections and
///          handle requests using a templated service type. It is designed to
///          run asynchronously and can handle multiple connections
///          concurrently.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class HttpServer : public std::enable_shared_from_this<HttpServer<ServiceT>>,
                   public Server<ServiceT> {
 public:
  /// @brief Constructor that initializes the HTTP server with a shared
  /// io_context,
  ///          a local endpoint, a request callback, a worker, and a timeout
  ///          duration.
  /// @param ioc, the shared io_context to use for asynchronous operations.
  /// @param local_endpoint, the local endpoint to bind the server to.
  /// @param request_cb, the callback function to handle incoming requests.
  /// @param worker, the shared worker to process requests.
  /// @param timeout, the timeout duration for operations.
  HttpServer(
      std::shared_ptr<boost::asio::io_context> ioc,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      std::function<typename ServiceT::ResponseT(typename ServiceT::RequestT)>
          request_cb,
      std::shared_ptr<simpleio::Worker> worker,
      std::chrono::duration<int> timeout)
      : ioc_(std::move(ioc)),
        acceptor_(*ioc_),
        timeout_(timeout),
        Server<ServiceT>(std::move(request_cb), std::move(worker)) {
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
      throw TransportException("bind");
    }

    acceptor_.listen(boost::asio::socket_base::max_listen_connections,
                     err_code);
    if (err_code) {
      throw TransportException("listen");
    }
  }

  /// @brief Destructor that closes the acceptor and logs the shutdown.
  /// @details This destructor ensures that the acceptor is closed gracefully
  ///          when the HttpServer object is destroyed, preventing any further
  ///          incoming connections.
  ~HttpServer() {
    BOOST_LOG_TRIVIAL(debug) << "HttpServer shutting down.";
    boost::beast::error_code err_code;
    acceptor_.close(err_code);
    if (err_code) {
      BOOST_LOG_TRIVIAL(error)
          << "HttpServer failed to close acceptor: " << err_code.message();
    }
  }

  /// @brief Starts the HTTP server and begins accepting incoming connections.
  void start() {
    BOOST_LOG_TRIVIAL(debug) << "HttpServer starting.";
    start_accepting();
  }

 private:
  /// @brief Starts accepting incoming connections asynchronously.
  void start_accepting() {
    BOOST_LOG_TRIVIAL(debug)
        << "HttpServer started, start accepting connections.";
    acceptor_.async_accept(
        *ioc_, boost::beast::bind_front_handler(&HttpServer<ServiceT>::accept,
                                                this->shared_from_this()));
  }

  /// @brief Accepts an incoming connection and starts a new session to handle
  /// it.
  void accept(boost::beast::error_code err_code,
              boost::asio::ip::tcp::socket socket) {
    if (err_code) {
      return fail(err_code, "accept");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpServer accepted a connection.";

    std::make_shared<HttpServerSession<ServiceT>>(
        this->request_cb_, this->worker_, timeout_, std::move(socket))
        ->run();

    start_accepting();
  }

  std::shared_ptr<boost::asio::io_context> ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::chrono::duration<int> timeout_;
};
}  // namespace simpleio::transports::ip
