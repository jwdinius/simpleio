// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/version.hpp>
#include <boost/log/trivial.hpp>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "simpleio/transport.hpp"
#include "simpleio/transports/ip/http.hpp"
#include "simpleio/transports/ip/tls.hpp"

namespace simpleio::transports::ip {

template <typename ServiceT>
class HttpsClient : public std::enable_shared_from_this<HttpsClient<ServiceT>>,
                    public Client<ServiceT> {
 public:
  // Objects are constructed with a strand to
  // ensure that handlers do not execute concurrently.
  explicit HttpsClient(std::shared_ptr<boost::asio::io_context> const& ioc,
                       TlsConfig const& tls_config,
                       boost::asio::ip::tcp::endpoint remote_endpoint,
                       std::shared_ptr<simpleio::Worker> const& worker,
                       std::chrono::duration<int> timeout)
      : io_ctx_(ioc),
        remote_endpoint_(std::move(remote_endpoint)),
        ssl_ctx_(boost::asio::ssl::context::tlsv13),
        stream_(*ioc, ssl_ctx_),
        timeout_(timeout),
        Client<ServiceT>(worker) {
    try {
      ssl_ctx_.load_verify_file(tls_config.ca_file.string());
      ssl_ctx_.use_certificate_chain_file(tls_config.cert_file.string());
      ssl_ctx_.use_private_key_file(tls_config.key_file.string(),
                                    boost::asio::ssl::context::pem);
    } catch (std::exception const& e) {
      std::ostringstream err;
      err << "TLSv1.3 setup failed: " << e.what();
      BOOST_LOG_TRIVIAL(error) << err.str();
      throw TransportException(err.str());
    }
  }

  std::future<typename ServiceT::ResponseT> send_request_async(
      typename ServiceT::RequestT const& req) override {
    req_ = req.entity();
    promise_ = std::make_shared<std::promise<typename ServiceT::ResponseT>>();
    connect();
    return promise_->get_future();
  }

  typename ServiceT::ResponseT send_request(
      typename ServiceT::RequestT const& req) override {
    auto future = send_request_async(req);
    // Wait for the future to complete and return the response
    if (!future.valid()) {
      throw TransportException(
          "Failed to get a valid response from the HttpsClient.");
    }
    return future.get();
  }

 private:
  void connect() {
    BOOST_LOG_TRIVIAL(debug) << "HttpsClient connecting.";
    // Reset the stream
    stream_ =
        boost::beast::ssl_stream<boost::beast::tcp_stream>(*io_ctx_, ssl_ctx_);
    stream_.next_layer().expires_after(timeout_);
    stream_.next_layer().async_connect(
        remote_endpoint_,
        boost::beast::bind_front_handler(
            &HttpsClient<ServiceT>::start_handshake, this->shared_from_this()));
  }

  void start_handshake(boost::beast::error_code err_code) {
    if (err_code) {
      return fail(err_code, "Connection failed.");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "HttpsClient connected, starting TLS handshake.";

    // Set a timeout on the operation
    stream_.next_layer().expires_after(timeout_);

    // Perform the TLS handshake
    stream_.async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::beast::bind_front_handler(&HttpsClient<ServiceT>::write_request,
                                         this->shared_from_this()));
  }
  void write_request(boost::beast::error_code err_code) {
    if (err_code) {
      return fail(err_code, "Connection failed.");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "HttpsClient handshake completed, sending request.";

    // Set a timeout on the operation
    stream_.next_layer().expires_after(timeout_);

    // Send the HTTP request to the remote host
    boost::beast::http::async_write(
        stream_, req_,
        boost::beast::bind_front_handler(&HttpsClient<ServiceT>::await_response,
                                         this->shared_from_this()));
  }

  void await_response(boost::beast::error_code err_code,
                      std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "Failed to send request.");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpsClient sent request, awaiting response.";

    // Receive the HTTP response
    boost::beast::http::async_read(
        stream_, buffer_, res_,
        boost::beast::bind_front_handler(
            &HttpsClient<ServiceT>::handle_response, this->shared_from_this()));
  }

  void handle_response(boost::beast::error_code err_code,
                       std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "Failed to read response.");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpsClient received response.";

    promise_->set_value(typename ServiceT::ResponseT(std::move(res_)));

    auto self = this->shared_from_this();
    stream_.async_shutdown([self](boost::beast::error_code err_code) mutable {
      BOOST_LOG_TRIVIAL(debug)
          << "HttpsClient handled response, closing connection.";
      if (err_code && err_code != boost::asio::error::eof) {
        BOOST_LOG_TRIVIAL(error)
            << "HttpsClient TLS shutdown failed: " << err_code.message();
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

template <typename ServiceT>
class HttpsServerSession
    : public std::enable_shared_from_this<HttpsServerSession<ServiceT>> {
 public:
  explicit HttpsServerSession(
      typename Server<ServiceT>::request_callback_t request_cb,
      std::shared_ptr<Worker> worker, std::chrono::duration<int> timeout,
      boost::asio::ip::tcp::socket&& socket,
      std::shared_ptr<boost::asio::ssl::context> const& ssl_ctx)
      : request_cb_(request_cb),
        worker_(std::move(worker)),
        timeout_(timeout),
        stream_(std::move(socket), *ssl_ctx) {}

  void run() {
    stream_.async_handshake(boost::asio::ssl::stream_base::server,
                            boost::beast::bind_front_handler(
                                &HttpsServerSession<ServiceT>::await_request,
                                this->shared_from_this()));
  }

 private:
  void await_request(boost::beast::error_code err_code) {
    if (err_code) {
      return fail(err_code, "handshake");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpsServerSession running, awaiting request.";
    req_ = {};
    stream_.next_layer().expires_after(timeout_);
    boost::beast::http::async_read(
        stream_, buffer_, req_,
        boost::beast::bind_front_handler(
            &HttpsServerSession<ServiceT>::handle_request,
            this->shared_from_this()));
  }

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
        << "HttpsServerSession received request and is handling it.";

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
                &HttpsServerSession<ServiceT>::teardown, self, keep_alive));
      });
    });
  }

  void teardown(bool _close, boost::beast::error_code err_code,
                std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (err_code) {
      return fail(err_code, "write");
    }
    BOOST_LOG_TRIVIAL(debug)
        << "HttpsServerSession handled request and sent response.";

    if (_close) {
      return close();
    }

    await_request(err_code);
  }

  void close() {
    auto self = this->shared_from_this();
    stream_.async_shutdown([self](boost::beast::error_code err_code) mutable {
      BOOST_LOG_TRIVIAL(debug) << "HttpsServerSession closing connection.";
      if (err_code && err_code != boost::asio::error::eof) {
        BOOST_LOG_TRIVIAL(error)
            << "HttpsServerSession TLS shutdown failed: " << err_code.message();
      }
    });
  }

  typename Server<ServiceT>::request_callback_t request_cb_;
  std::shared_ptr<Worker> worker_;
  std::chrono::duration<int> timeout_;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  typename ServiceT::RequestT::entity_t req_;
  typename ServiceT::ResponseT::entity_t res_;
};

template <typename ServiceT>
class HttpsServer : public std::enable_shared_from_this<HttpsServer<ServiceT>>,
                    public Server<ServiceT> {
 public:
  HttpsServer(
      std::shared_ptr<boost::asio::io_context> ioc, TlsConfig const& tls_config,
      boost::asio::ip::tcp::endpoint const& local_endpoint,
      std::function<typename ServiceT::ResponseT(typename ServiceT::RequestT)>
          request_cb,
      std::shared_ptr<simpleio::Worker> worker,
      std::chrono::duration<int> timeout)
      : ioc_(std::move(ioc)),
        ssl_ctx_(std::make_shared<boost::asio::ssl::context>(
            boost::asio::ssl::context::tlsv13)),
        acceptor_(*ioc_),
        timeout_(timeout),
        Server<ServiceT>(std::move(request_cb), std::move(worker)) {
    try {
      ssl_ctx_->load_verify_file(tls_config.ca_file.string());
      ssl_ctx_->use_certificate_chain_file(tls_config.cert_file.string());
      ssl_ctx_->use_private_key_file(tls_config.key_file.string(),
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

  ~HttpsServer() {
    BOOST_LOG_TRIVIAL(debug) << "HttpsServer shutting down.";
    boost::beast::error_code err_code;
    acceptor_.close(err_code);
    if (err_code) {
      BOOST_LOG_TRIVIAL(error)
          << "HttpsServer failed to close acceptor: " << err_code.message();
    }
  }

  void start() {
    BOOST_LOG_TRIVIAL(debug) << "HttpsServer starting.";
    start_accepting();
  }

 private:
  void start_accepting() {
    BOOST_LOG_TRIVIAL(debug)
        << "HttpsServer started, start accepting connections.";
    acceptor_.async_accept(
        *ioc_, boost::beast::bind_front_handler(&HttpsServer<ServiceT>::accept,
                                                this->shared_from_this()));
  }

  void accept(boost::beast::error_code err_code,
              boost::asio::ip::tcp::socket socket) {
    if (err_code) {
      return fail(err_code, "accept");
    }
    BOOST_LOG_TRIVIAL(debug) << "HttpsServer accepted a connection.";

    std::make_shared<HttpsServerSession<ServiceT>>(
        this->request_cb_, this->worker_, timeout_, std::move(socket), ssl_ctx_)
        ->run();

    start_accepting();
  }

  std::shared_ptr<boost::asio::io_context> ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::shared_ptr<boost::asio::ssl::context> ssl_ctx_;
  std::chrono::duration<int> timeout_;
};
}  // namespace simpleio::transports::ip
