// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/ip/http.hpp"

#include <boost/log/trivial.hpp>
#include <memory>
#include <string>
#include <utility>

namespace sio = simpleio;
namespace siotrns = simpleio::transports;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Report a failure
void fail(beast::error_code ec, char const* what) {
  BOOST_LOG_TRIVIAL(error) << what << ": " << ec.message();
}

siotrns::ip::HttpClientSession::HttpClientSession(
    std::shared_ptr<net::io_context> const& ioc,
    siotrns::ip::HttpOptions const& options)
    : io_ctx_(std::move(ioc)),
      resolver_(*io_ctx_),
      stream_(*io_ctx_),
      options_(options) {
  req_.version(static_cast<int>(options_.version));
  req_.method(options_.method);
  req_.target(options_.target);
  req_.set(http::field::host, options_.ip_address);
  req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
}

void siotrns::ip::HttpClientSession::send(std::string const& request) {
  req_.body() = request;
  req_.prepare_payload();

  // Look up the domain name
  resolver_.async_resolve(
      options_.ip_address, std::to_string(options_.port),
      beast::bind_front_handler(&HttpClientSession::on_resolve,
                                shared_from_this()));
}

void siotrns::ip::HttpClientSession::set_response_callback(
    std::function<void(std::string const&)> callback) {
  response_callback_ = std::move(callback);
}

void siotrns::ip::HttpClientSession::on_resolve(
    beast::error_code ec, tcp::resolver::results_type results) {
  if (ec) return fail(ec, "resolve");

  // Set a timeout on the operation
  stream_.expires_after(std::chrono::seconds(30));

  // Make the connection on the IP address we get from a lookup
  stream_.async_connect(
      results, beast::bind_front_handler(&HttpClientSession::on_connect,
                                         shared_from_this()));
}

void siotrns::ip::HttpClientSession::on_connect(
    beast::error_code ec, tcp::resolver::results_type::endpoint_type) {
  if (ec) return fail(ec, "connect");

  // Set a timeout on the operation
  stream_.expires_after(std::chrono::seconds(30));

  // Send the HTTP request to the remote host
  http::async_write(stream_, req_,
                    beast::bind_front_handler(&HttpClientSession::on_write,
                                              shared_from_this()));
}

void siotrns::ip::HttpClientSession::on_write(beast::error_code ec,
                                              std::size_t bytes_transferred) {
  boost::ignore_unused(bytes_transferred);

  if (ec) return fail(ec, "write");

  // Receive the HTTP response
  http::async_read(stream_, buffer_, res_,
                   beast::bind_front_handler(&HttpClientSession::on_read,
                                             shared_from_this()));
}

void siotrns::ip::HttpClientSession::on_read(beast::error_code ec,
                                             std::size_t bytes_transferred) {
  boost::ignore_unused(bytes_transferred);

  if (ec) return fail(ec, "read");

  response_callback_(res_.body());

  // Gracefully close the socket
  stream_.socket().shutdown(tcp::socket::shutdown_both, ec);

  // not_connected happens sometimes so don't bother reporting it.
  if (ec && ec != beast::errc::not_connected) return fail(ec, "shutdown");

  // If we get here then the connection is closed gracefully
}

siotrns::ip::HttpClientSendStrategy::HttpClientSendStrategy(
    std::shared_ptr<siotrns::ip::HttpClientSession> session)
    : session_(std::move(session)) {}

void siotrns::ip::HttpClientSendStrategy::send(std::string const& blob) {
  session_->send(blob);
}

siotrns::ip::HttpClientReceiveStrategy::HttpClientReceiveStrategy(
    std::shared_ptr<siotrns::ip::HttpClientSession> session)
    : session_(std::move(session)) {
  session_->set_response_callback(
      [this](const std::string& blob) { return event_cb_(blob); });
}

siotrns::ip::HttpServerSession::HttpServerSession(tcp::socket&& socket)
    : stream_(std::move(socket)) {}

void siotrns::ip::HttpServerSession::run() {
  // We need to be executing within a strand to perform async operations
  // on the I/O objects in this session. Although not strictly necessary
  // for single-threaded contexts, this example code is written to be
  // thread-safe by default.
  net::dispatch(stream_.get_executor(),
                beast::bind_front_handler(&HttpServerSession::do_read,
                                          shared_from_this()));
}

siotrns::ip::HttpServerSession::set_request_callback(
    std::function<void(std::string const&)> callback) {
  request_callback_ = std::move(callback);
}

void siotrns::ip::HttpServerSession::do_read() {
  // Make the request empty before reading,
  // otherwise the operation behavior is undefined.
  req_ = {};

  // Set the timeout.
  stream_.expires_after(std::chrono::seconds(30));

  // Read a request
  http::async_read(stream_, buffer_, req_,
                   beast::bind_front_handler(&HttpServerSession::on_read,
                                             shared_from_this()));
}

void siotrns::ip::HttpServerSession::on_read(beast::error_code ec,
                                             std::size_t bytes_transferred) {
  boost::ignore_unused(bytes_transferred);

  // This means they closed the connection
  if (ec == http::error::end_of_stream) return do_close();

  if (ec) return fail(ec, "read");

  try {
    request_callback_(req_.body());
  } catch (const HttpServerException& e) {
    ec = beast::http::make_error_code(e.code());
    fail(ec, e.what());
  }
  // TODO(jwdinius): form response
}

void siotrns::ip::HttpServerSession::on_write(bool close, beast::error_code ec,
                                              std::size_t bytes_transferred) {
  boost::ignore_unused(bytes_transferred);

  if (ec) return fail(ec, "write");

  if (close) {
    // This means we should close the connection, usually because
    // the response indicated the "Connection: close" semantic.
    return do_close();
  }

  // We're done with the response so delete it
  res_ = nullptr;

  // Read another request
  do_read();
}

void siotrns::ip::HttpServerSession::do_close() {
  // Send a TCP shutdown
  beast::error_code ec;
  stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

  // At this point the connection is closed gracefully
}

siotrns::ip::HttpListener::HttpListener(
    std::shared_ptr<boost::asio::io_context> ioc,
    boost::asio::ip::tcp::endpoint endpoint, )
    : ioc_(std::move(ioc)), acceptor_(*ioc_) {
  beast::error_code ec;

  // Open the acceptor
  acceptor_.open(endpoint.protocol(), ec);
  if (ec) {
    fail(ec, "open");
    return;
  }

  // Allow address reuse
  acceptor_.set_option(net::socket_base::reuse_address(true), ec);
  if (ec) {
    fail(ec, "set_option");
    return;
  }

  // Bind to the server address
  acceptor_.bind(endpoint, ec);
  if (ec) {
    fail(ec, "bind");
    return;
  }

  // Start listening for connections
  acceptor_.listen(net::socket_base::max_listen_connections, ec);
  if (ec) {
    fail(ec, "listen");
    return;
  }
}

// Start accepting incoming connections
void siotrns::ip::HttpListener::run() {
  do_accept();
}

void siotrns::ip::HttpListener::do_accept() {
  // The new connection gets its own strand
  acceptor_.async_accept(
      *ioc_,
      beast::bind_front_handler(&HttpListener::on_accept, shared_from_this()));
}

void siotrns::ip::HttpListener::on_accept(boost::beast::error_code ec,
                                          boost::asio::ip::tcp::socket socket) {
  if (ec) {
    fail(ec, "accept");
  } else {
    // Create the session and run it
    std::make_shared<HttpServerSession>(std::move(socket))->run();
  }

  // Accept another connection
  do_accept();
}
