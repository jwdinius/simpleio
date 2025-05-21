// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <functional>
#include <memory>
#include <string>

#include "simpleio/transport.hpp"

namespace simpleio::transports::ip {

enum class HttpVersion : int {
  V1_0 = 10,
  V1_1 = 11,
  V2_0 = 20,
};

struct HttpOptions {
  std::string ip_address;
  uint16_t port;
  boost::beast::http::verb method;
  std::string target;
  HttpVersion version;
  std::string content_type;
};

// Performs an HTTP GET and prints the response
class HttpClientSession
    : public std::enable_shared_from_this<HttpClientSession> {
 public:
  // Objects are constructed with a strand to
  // ensure that handlers do not execute concurrently.
  explicit HttpClientSession(
      std::shared_ptr<boost::asio::io_context> const& ioc,
      HttpOptions const& options);

  void send(std::string const& blob);

  void set_response_callback(std::function<void(std::string const&)> callback);

 private:
  void on_resolve(boost::beast::error_code ec,
                  boost::asio::ip::tcp::resolver::results_type results);

  void on_connect(boost::beast::error_code ec,
                  boost::asio::ip::tcp::resolver::results_type::endpoint_type);

  void on_write(boost::beast::error_code ec, std::size_t bytes_transferred);

  void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

  std::shared_ptr<boost::asio::io_context> io_ctx_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::beast::tcp_stream stream_;
  HttpOptions const options_;
  std::function<void(std::string const&)> response_callback_;
  boost::beast::flat_buffer buffer_;  // (Must persist between reads)
  boost::beast::http::request<boost::beast::http::string_body> req_;
  boost::beast::http::response<boost::beast::http::string_body> res_;
};

class HttpClientSendStrategy : public SendStrategy {
 public:
  explicit HttpClientSendStrategy(std::shared_ptr<HttpClientSession> session);

  void send(std::string const& blob) override;

 private:
  std::shared_ptr<HttpClientSession> session_;
};

class HttpClientReceiveStrategy : public ReceiveStrategy {
 public:
  explicit HttpClientReceiveStrategy(
      std::shared_ptr<HttpClientSession> session);

 private:
  std::shared_ptr<HttpClientSession> session_;
};

// Handles an HTTP server connection
class HttpServerSession
    : public std::enable_shared_from_this<HttpServerSession> {
 public:
  // Take ownership of the stream
  HttpServerSession(
      boost::asio::ip::tcp::socket&& socket);  // NOLINT [runtime/explicit]

  // Start the asynchronous operation
  void run();

  void set_request_callback(std::function<void(std::string const&)> callback);

 private:
  void do_read();

  void on_read(boost::beast::error_code ec, std::size_t bytes_transferred);

  void on_write(bool close, boost::beast::error_code ec,
                std::size_t bytes_transferred);

  void do_close();

  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;
  boost::beast::http::request<http::string_body> req_;
  boost::beast::http::response<http::string_body> res_;
  std::function<void(std::string const&)> request_callback_;
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class HttpListener : public std::enable_shared_from_this<HttpListener> {
 public:
  HttpListener(std::shared_ptr<boost::asio::io_context> ioc,
               boost::asio::ip::tcp::endpoint endpoint);

  // Start accepting incoming connections
  void run();

 private:
  void do_accept();

  void on_accept(boost::beast::error_code ec,
                 boost::asio::ip::tcp::socket socket);

  std::shared_ptr<boost::asio::io_context> ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace simpleio::transports::ip
