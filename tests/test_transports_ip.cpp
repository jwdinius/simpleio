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
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "certs_path.h"  // NOLINT [build/include_subdir]
#include "simpleio/transports/ip/ip.hpp"

namespace asio = boost::asio;
namespace blog = boost::log;
namespace sio = simpleio;
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

class SimpleStringSerializer : public sio::SerializationStrategy<std::string> {
 public:
  std::vector<std::byte> serialize(std::string const& entity) override {
    std::vector<std::byte> blob(entity.size());
    std::memcpy(blob.data(), entity.data(), entity.size());
    return blob;
  }

  std::string deserialize(std::vector<std::byte> const& blob) override {
    return {reinterpret_cast<char const*>(blob.data()), blob.size()};
  }
};

class SimpleString : public sio::Message<std::string> {
 public:
  explicit SimpleString(
      std::shared_ptr<sio::SerializationStrategy<std::string>> serializer)
      : sio::Message<std::string>(std::string("Hello, World!"),
                                  std::move(serializer)) {}

  SimpleString(
      std::vector<std::byte> const& blob,
      std::shared_ptr<sio::SerializationStrategy<std::string>> serializer)
      : sio::Message<std::string>(blob, std::move(serializer)) {}
};

class TestNetworkTransport : public ::testing::Test {
 public:
  TestNetworkTransport()
      : string_serializer_(std::make_shared<SimpleStringSerializer>()),
        message_(string_serializer_) {
    BOOST_LOG_TRIVIAL(debug) << "TestNetworkTransport constructor";

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
    io_worker_.reset();
  }

 protected:
  std::shared_ptr<SimpleStringSerializer> string_serializer_;
  SimpleString message_;
  size_t num_calls_{0};
  std::mutex mutex_;
  std::condition_variable cv_;
  std::function<void(SimpleString const&)> message_cb_;
  std::shared_ptr<siotrns::ip::IoWorker> io_worker_;
  std::function<void(std::shared_ptr<sio::Sender<SimpleString>>)> test_fn_;
};

/// @brief Test for Scheme::TCP with an IPv4 address
TEST_F(TestNetworkTransport, TestTcpIPv4) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_ip = TEST_IPV4_ADDR,
                                                .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TCP, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_IPV4_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TCP, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::TCP with an IPv6 address
TEST_F(TestNetworkTransport, TestTcpIPv6) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_ip = TEST_IPV6_ADDR,
                                                .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TCP, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_IPV6_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TCP, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::TLS with an IPv4 address
TEST_F(TestNetworkTransport, TestTlsIPv4) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{
      .local_ip = TEST_IPV4_ADDR,
      .local_port = TEST_PORT_NUM,
      .tls_config = siotrns::ip::TlsConfig{
          .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
          .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
          .key_file =
              std::filesystem::path(CERTS_PATH) / "private/receiver.key"}};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TLS, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{
      .remote_ip = TEST_IPV4_ADDR,
      .remote_port = TEST_PORT_NUM,
      .tls_config = siotrns::ip::TlsConfig{
          .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
          .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
          .key_file =
              std::filesystem::path(CERTS_PATH) / "private/sender.key"}};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TLS, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::TLS with an IPv6 address
TEST_F(TestNetworkTransport, TestTlsIPv6) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{
      .local_ip = TEST_IPV6_ADDR,
      .local_port = TEST_PORT_NUM,
      .tls_config = siotrns::ip::TlsConfig{
          .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
          .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
          .key_file =
              std::filesystem::path(CERTS_PATH) / "private/receiver.key"}};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TLS, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{
      .remote_ip = TEST_IPV6_ADDR,
      .remote_port = TEST_PORT_NUM,
      .tls_config = siotrns::ip::TlsConfig{
          .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
          .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
          .key_file =
              std::filesystem::path(CERTS_PATH) / "private/sender.key"}};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TLS, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP with an IPv4 address
TEST_F(TestNetworkTransport, TestUdpIPv4) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_ip = TEST_IPV4_ADDR,
                                                .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_IPV4_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP with an IPv6 address
TEST_F(TestNetworkTransport, TestUdpIPv6) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_ip = TEST_IPV6_ADDR,
                                                .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, string_serializer_, message_cb_,
      rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_IPV6_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP_BROADCAST with an IPv4 address
TEST_F(TestNetworkTransport, TestUdpBroadcastIPv4) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_BROADCAST, string_serializer_,
      message_cb_, rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_BROADCAST_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_BROADCAST, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP_BROADCAST with an IPv6 address
/// @details This should fail because IPv6 does not support broadcast.
TEST_F(TestNetworkTransport, TestUdpBroadcastIPv6) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{.local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_BROADCAST, string_serializer_,
      message_cb_, rcvr_opts);
  auto sndr_opts = siotrns::ip::SenderOptions{.remote_ip = TEST_IPV6_ADDR,
                                              .remote_port = TEST_PORT_NUM};
  EXPECT_THROW(siotrns::ip::make_sender<SimpleString>(
                   io_worker_, siotrns::ip::Scheme::UDP_BROADCAST, sndr_opts),
               sio::TransportException);
}

/// @brief Test for Scheme::UDP_MULTICAST with an IPv4 address
TEST_F(TestNetworkTransport, TestUdpMulticastIPv4) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{
      .local_ip = TEST_IPV4_MULTICAST_ADDR, .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_MULTICAST, string_serializer_,
      message_cb_, rcvr_opts);
  auto sndr_opts =
      siotrns::ip::SenderOptions{.remote_ip = TEST_IPV4_MULTICAST_ADDR,
                                 .remote_port = TEST_PORT_NUM,
                                 .hops = 1,
                                 .loopback = true};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_MULTICAST, sndr_opts);

  test_fn_(sndr);
}

/// @brief Test for Scheme::UDP_MULTICAST with an IPv6 address
TEST_F(TestNetworkTransport, TestUdpMulticastIPv6) {
  auto rcvr_opts = siotrns::ip::ReceiverOptions{
      .local_ip = TEST_IPV6_MULTICAST_ADDR, .local_port = TEST_PORT_NUM};
  auto rcvr = siotrns::ip::make_receiver<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_MULTICAST, string_serializer_,
      message_cb_, rcvr_opts);
  auto sndr_opts =
      siotrns::ip::SenderOptions{.remote_ip = TEST_IPV6_MULTICAST_ADDR,
                                 .remote_port = TEST_PORT_NUM,
                                 .hops = 1,
                                 .loopback = true};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP_MULTICAST, sndr_opts);

  test_fn_(sndr);
}

// NOLINTBEGIN [bugprone-exception-escape]
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  init_logger();
  return RUN_ALL_TESTS();
}
// NOLINTEND [bugprone-exception-escape]
