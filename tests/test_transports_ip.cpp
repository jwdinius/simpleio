// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/log/attributes/clock.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "certs_path.h"  // NOLINT [build/include_subdir]
#include "simpleio/messages/http.hpp"
#include "simpleio/transports/ip/ip.hpp"

namespace asio = boost::asio;
namespace blog = boost::log;
namespace sio = simpleio;
namespace siomsg = simpleio::messages;
namespace siotrns = simpleio::transports;

void init_logger() {
  blog::core::get()->add_global_attribute("TimeStamp",
                                          blog::attributes::local_clock());
  blog::add_console_log(std::clog, blog::keywords::format =
                                       "[%TimeStamp%] [%Severity%] %Message%");
  blog::core::get()->set_filter(blog::trivial::severity >=
                                blog::trivial::debug);
}

static constexpr const char* TEST_IPV4_ADDR = "127.0.0.1";
static constexpr const char* TEST_BROADCAST_ADDR = "255.255.255.255";
static constexpr const char* TEST_IPV4_MULTICAST_ADDR = "239.255.0.1";
static constexpr const char* TEST_IPV6_ADDR = "::1";
static constexpr const char* TEST_IPV6_MULTICAST_ADDR = "ff02::1";
static constexpr uint16_t TEST_PORT_NUM = 12345;
static constexpr size_t MAX_ITERS = 10;
static constexpr uint8_t NUM_IO_WORKER_THREADS = 2;

class SimpleStringSerializer : public sio::Serializer<std::string> {
 public:
  std::string serialize(std::string const& entity) override {
    return entity;
  }

  std::string deserialize(std::string const& blob) override {
    return blob;
  }
};

class SimpleString : public sio::Message<SimpleStringSerializer> {
 public:
  SimpleString() : sio::Message<SimpleStringSerializer>("Hello, World!") {}

  explicit SimpleString(std::string const& blob)
      : sio::Message<SimpleStringSerializer>(blob) {}
};

class TestNetworkTransportSendReceive : public ::testing::Test {
 public:
  TestNetworkTransportSendReceive() : message_() {
    BOOST_LOG_TRIVIAL(debug) << "TestNetworkTransport constructor";

    io_worker_ = std::make_shared<siotrns::ip::IoWorker>(NUM_IO_WORKER_THREADS);

    /// @brief Callback function to handle received messages.
    /// @details Check that the received message matches the expected
    ///          message and increment the call count.
    message_cb_ = [this](SimpleString const& received) {
      std::lock_guard lock(mutex_);
      BOOST_LOG_TRIVIAL(debug)
          << "Received message: \"" << received.entity() << "\"";
      EXPECT_EQ(received.entity(), message_.entity());
      if (++num_calls_ == MAX_ITERS) {
        cv_.notify_one();
      }
    };

    /// @brief Test function to send messages.
    /// @details Send the message MAX_ITERS times and wait for message_cb_
    ///          to be called MAX_ITERS times.
    test_fn_ = [this](std::shared_ptr<sio::Sender<SimpleString>> sndr) {
      for (int i = 0; i < MAX_ITERS; i++) {
        sndr->send(message_);
      }
      {
        std::unique_lock lock(mutex_);
        EXPECT_TRUE(cv_.wait_for(lock, std::chrono::milliseconds(100),
                                 [this] { return num_calls_ == MAX_ITERS; }));
      }
    };
  }

  void SetUp() override {
    io_worker_ = std::make_shared<siotrns::ip::IoWorker>();
    num_calls_ = 0;
  }

  void TearDown() override {
    io_worker_->scheduler().reset();
    io_worker_.reset();
  }

 protected:
  SimpleString message_;
  size_t num_calls_{0};
  std::mutex mutex_;
  std::condition_variable cv_;
  std::function<void(SimpleString const&)> message_cb_;
  std::shared_ptr<siotrns::ip::IoWorker> io_worker_;
  std::function<void(std::shared_ptr<sio::Sender<SimpleString>>)> test_fn_;
};

/// @brief Test for TCP with an IPv4 address
TEST_F(TestNetworkTransportSendReceive, TestTcpIPv4) {
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV4_ADDR, TEST_PORT_NUM);
  auto rcvr = siotrns::ip::tcp::Receiver<SimpleString>::create(
      io_worker_->scheduler(), endpoint, std::move(message_cb_));
  auto sndr = std::make_shared<siotrns::ip::tcp::Sender<SimpleString>>(
      io_worker_->scheduler(), endpoint);
  test_fn_(sndr);
}

/// @brief Test for TCP with an IPv6 address
TEST_F(TestNetworkTransportSendReceive, TestTcpIPv6) {
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM);
  auto rcvr = siotrns::ip::tcp::Receiver<SimpleString>::create(
      io_worker_->scheduler(), endpoint, std::move(message_cb_));
  auto sndr = std::make_shared<siotrns::ip::tcp::Sender<SimpleString>>(
      io_worker_->scheduler(), endpoint);
  test_fn_(sndr);
}

/// @brief Test for TLS with an IPv4 address
TEST_F(TestNetworkTransportSendReceive, TestTlsIPv4) {
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV4_ADDR, TEST_PORT_NUM);
  auto rcvr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};
  auto rcvr = siotrns::ip::tls::Receiver<SimpleString>::create(
      io_worker_->scheduler(), endpoint, std::move(message_cb_), rcvr_cert);
  auto sndr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};
  auto sndr = std::make_shared<siotrns::ip::tls::Sender<SimpleString>>(
      io_worker_->scheduler(), endpoint, sndr_cert);
  test_fn_(sndr);
}

/// @brief Test for TLS with an IPv6 address
TEST_F(TestNetworkTransportSendReceive, TestTlsIPv6) {
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM);
  auto rcvr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};
  auto rcvr = siotrns::ip::tls::Receiver<SimpleString>::create(
      io_worker_->scheduler(), endpoint, std::move(message_cb_), rcvr_cert);
  auto sndr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};
  auto sndr = std::make_shared<siotrns::ip::tls::Sender<SimpleString>>(
      io_worker_->scheduler(), endpoint, sndr_cert);
  test_fn_(sndr);
}

/// @brief Test UDP with an IPv4 address
TEST_F(TestNetworkTransportSendReceive, TestUdpIPv4) {
  auto endpoint =
      siotrns::ip::udp::create_endpoint(TEST_IPV4_ADDR, TEST_PORT_NUM);
  auto rcvr = siotrns::ip::udp::Receiver<SimpleString>::create_unicast(
      io_worker_->scheduler(), endpoint, std::move(message_cb_));
  auto sndr = siotrns::ip::udp::Sender<SimpleString>::create_unicast(
      io_worker_->scheduler(), endpoint);
  test_fn_(sndr);
}

/// @brief Test UDP with an IPv6 address
TEST_F(TestNetworkTransportSendReceive, TestUdpIPv6) {
  auto endpoint =
      siotrns::ip::udp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM);
  auto rcvr = siotrns::ip::udp::Receiver<SimpleString>::create_unicast(
      io_worker_->scheduler(), endpoint, std::move(message_cb_));
  auto sndr = siotrns::ip::udp::Sender<SimpleString>::create_unicast(
      io_worker_->scheduler(), endpoint);
  test_fn_(sndr);
}

/// @brief Test UDP with a broadcast address (IPv4 only)
TEST_F(TestNetworkTransportSendReceive, TestUdpBroadcastIPv4) {
  auto rcvr = siotrns::ip::udp::Receiver<SimpleString>::create_broadcast(
      io_worker_->scheduler(), TEST_PORT_NUM, std::move(message_cb_));
  auto broadcast_endpoint =
      siotrns::ip::udp::create_endpoint(TEST_BROADCAST_ADDR, TEST_PORT_NUM);
  auto sndr = siotrns::ip::udp::Sender<SimpleString>::create_broadcast(
      io_worker_->scheduler(), broadcast_endpoint);
  test_fn_(sndr);
}

/// @brief Test UDP with an invalid broadcast address
TEST_F(TestNetworkTransportSendReceive, TestUdpBroadcastIPv6) {
  auto invalid_endpoint =
      siotrns::ip::udp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM);
  EXPECT_THROW(siotrns::ip::udp::Sender<SimpleString>::create_broadcast(
                   io_worker_->scheduler(), invalid_endpoint),
               sio::TransportException);
}

/// @brief Test UDP MULTICAST with an IPv4 address
TEST_F(TestNetworkTransportSendReceive, TestUdpMulticastIPv4) {
  auto endpoint = siotrns::ip::udp::create_endpoint(TEST_IPV4_MULTICAST_ADDR,
                                                    TEST_PORT_NUM);
  auto rcvr = siotrns::ip::udp::Receiver<SimpleString>::create_multicast(
      io_worker_->scheduler(), endpoint, std::move(message_cb_));
  auto sndr = siotrns::ip::udp::Sender<SimpleString>::create_multicast(
      io_worker_->scheduler(), endpoint, /* hops */ 1, /* loopback */ true);
  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP_MULTICAST with an IPv6 address
TEST_F(TestNetworkTransportSendReceive, TestUdpMulticastIPv6) {
  if (std::getenv("GITHUB_ACTIONS") != nullptr) {
    GTEST_SKIP() << "Skipping IPv6 multicast test on GitHub Actions";
  }
  auto endpoint = siotrns::ip::udp::create_endpoint(TEST_IPV6_MULTICAST_ADDR,
                                                    TEST_PORT_NUM);
  auto rcvr = siotrns::ip::udp::Receiver<SimpleString>::create_multicast(
      io_worker_->scheduler(), endpoint, std::move(message_cb_),
      /* interface_v6 */ 0);
  auto sndr = siotrns::ip::udp::Sender<SimpleString>::create_multicast(
      io_worker_->scheduler(), endpoint, /* hops */ 1, /* loopback */ true,
      /* interface_v6 */ 0);
  test_fn_(sndr);
}

using RequestT = siomsg::HttpRequestType<boost::beast::http::empty_body>;
using ResponseT = siomsg::HttpResponseType<boost::beast::http::string_body>;
using ReqSerializerT = siomsg::HttpRequestSerializer<RequestT>;
using ResSerializerT = siomsg::HttpResponseSerializer<ResponseT>;
using ServiceT = sio::Service<ReqSerializerT, ResSerializerT>;

class TestNetworkTransportRequestRespond : public ::testing::Test {
 public:
  TestNetworkTransportRequestRespond() {
    BOOST_LOG_TRIVIAL(debug) << "TestNetworkTransportClientServer constructor";

    /// @brief Test function to send messages.
    /// @details Send the message MAX_ITERS times and wait for message_cb_
    ///          to be called MAX_ITERS times.
    test_fn_ = [this](std::shared_ptr<sio::Client<ServiceT>> client) {
      for (int i = 0; i < MAX_ITERS; i++) {
        auto response = client->send_request(*request_);
        EXPECT_EQ(response.entity().result(), boost::beast::http::status::ok);
        EXPECT_EQ(response.entity().body(), "Hello, World!");
        while (io_worker_->scheduler()->poll() > 0) {
          // Keep polling until no more handlers are ready
          std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
      }
      {
        std::unique_lock lock(mutex_);
        EXPECT_TRUE(cv_.wait_for(lock, std::chrono::milliseconds(500),
                                 [this] { return num_calls_ == MAX_ITERS; }));
      }
    };

    /// @brief Callback function to handle received messages.
    /// @details Check that the received message matches the expected
    ///          message and increment the call count.
    request_cb_ = [this](typename ServiceT::RequestT const& request) ->
        typename ServiceT::ResponseT {
          std::lock_guard lock(mutex_);
          EXPECT_EQ(request.entity().method(), boost::beast::http::verb::get);
          EXPECT_EQ(request.entity().target(), "/");
          auto response_entity = ResponseT();
          response_entity.result(boost::beast::http::status::ok);
          response_entity.version(11);
          response_entity.set(boost::beast::http::field::content_type,
                              "text/plain");
          response_entity.set(boost::beast::http::field::server,
                              BOOST_BEAST_VERSION_STRING);
          response_entity.body() = "Hello, World!";
          response_entity.prepare_payload();
          if (++num_calls_ == MAX_ITERS) {
            cv_.notify_one();
          }
          return typename ServiceT::ResponseT(std::move(response_entity));
        };
  }

  /// @brief Create a request.
  void create_request(boost::asio::ip::tcp::endpoint endpoint) {
    auto req_entity = RequestT();
    req_entity.target("/");
    req_entity.version(11);
    req_entity.method(boost::beast::http::verb::get);
    req_entity.set(
        boost::beast::http::field::host,
        endpoint.address().to_string() + ":" + std::to_string(endpoint.port()));
    req_entity.set(boost::beast::http::field::user_agent,
                   BOOST_BEAST_VERSION_STRING);
    request_ =
        std::make_shared<typename ServiceT::RequestT>(std::move(req_entity));
  }

  void SetUp() override {
    io_worker_ = std::make_shared<siotrns::ip::IoWorker>();
    num_calls_ = 0;
  }

  void TearDown() override {
    io_worker_->scheduler().reset();
    io_worker_.reset();
  }

 protected:
  std::shared_ptr<typename ServiceT::RequestT> request_;
  size_t num_calls_{0};
  std::mutex mutex_;
  std::condition_variable cv_;
  typename sio::Server<ServiceT>::request_callback_t request_cb_;
  std::shared_ptr<siotrns::ip::IoWorker> io_worker_;
  std::function<void(std::shared_ptr<sio::Client<ServiceT>>)> test_fn_;
};

/// @brief Test HTTP with an IPv4 address
TEST_F(TestNetworkTransportRequestRespond, TestHttpIPv4) {
  auto timeout = std::chrono::seconds(1);
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV4_ADDR, TEST_PORT_NUM);
  auto server = siotrns::ip::http::Server<ServiceT>::create(
      io_worker_->scheduler(), endpoint, std::move(request_cb_), timeout);
  EXPECT_NE(server, nullptr);
  auto client = std::make_shared<siotrns::ip::http::Client<ServiceT>>(
      io_worker_->scheduler(), endpoint, timeout);
  EXPECT_NE(client, nullptr);

  create_request(endpoint);
  test_fn_(client);
  client.reset();  // Ensure client is reset after test
  server.reset();  // Ensure server is reset after test
}

/// @brief Test HTTP with an IPv6 address
TEST_F(TestNetworkTransportRequestRespond, TestHttpIPv6) {
  auto timeout = std::chrono::seconds(1);
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM);
  auto server = siotrns::ip::http::Server<ServiceT>::create(
      io_worker_->scheduler(), endpoint, std::move(request_cb_), timeout);
  EXPECT_NE(server, nullptr);
  auto client = std::make_shared<siotrns::ip::http::Client<ServiceT>>(
      io_worker_->scheduler(), endpoint, timeout);
  EXPECT_NE(client, nullptr);

  create_request(endpoint);
  test_fn_(client);
  client.reset();  // Ensure client is reset after test
  server.reset();  // Ensure server is reset after test
}

/// @brief Test HTTPS with an IPv4 address
TEST_F(TestNetworkTransportRequestRespond, TestHttpsIPv4) {
  auto timeout = std::chrono::seconds(1);
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV4_ADDR, TEST_PORT_NUM + 1);
  auto srvr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};
  auto server = siotrns::ip::https::Server<ServiceT>::create(
      io_worker_->scheduler(), endpoint, std::move(request_cb_), timeout,
      srvr_cert);
  EXPECT_NE(server, nullptr);
  auto client_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};
  auto client = std::make_shared<siotrns::ip::https::Client<ServiceT>>(
      io_worker_->scheduler(), endpoint, timeout, client_cert);
  EXPECT_NE(client, nullptr);

  create_request(endpoint);
  test_fn_(client);
  client.reset();  // Ensure client is reset after test
  server.reset();  // Ensure server is reset after test
}

/// @brief Test HTTPS with an IPv6 address
TEST_F(TestNetworkTransportRequestRespond, TestHttpsIPv6) {
  auto timeout = std::chrono::seconds(1);
  auto endpoint =
      siotrns::ip::tcp::create_endpoint(TEST_IPV6_ADDR, TEST_PORT_NUM + 1);
  auto srvr_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};
  auto server = siotrns::ip::https::Server<ServiceT>::create(
      io_worker_->scheduler(), endpoint, std::move(request_cb_), timeout,
      srvr_cert);
  EXPECT_NE(server, nullptr);
  auto client_cert = siotrns::ip::tls::Credentials{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};
  auto client = std::make_shared<siotrns::ip::https::Client<ServiceT>>(
      io_worker_->scheduler(), endpoint, timeout, client_cert);
  EXPECT_NE(client, nullptr);

  create_request(endpoint);
  test_fn_(client);
  client.reset();  // Ensure client is reset after test
  server.reset();  // Ensure server is reset after test
}

// NOLINTBEGIN [bugprone-exception-escape]
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  init_logger();
  return RUN_ALL_TESTS();
}
// NOLINTEND [bugprone-exception-escape]
