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
#include "simpleio/async_queue.hpp"
#include "simpleio/transports/tcp.hpp"
#include "simpleio/transports/tls.hpp"
#include "simpleio/transports/udp.hpp"

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

// NOLINTBEGIN[modernize-avoid-c-arrays]
static constexpr char TEST_IPV4_ADDR[] = "127.0.0.1";
// NOLINTEND[modernize-avoid-c-arrays]
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
  void SetUp() override {
    BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
    // Prevent io_context from exiting when idle
    work_guard_ = std::make_unique<
        asio::executor_work_guard<asio::io_context::executor_type>>(
        io_ctx_->get_executor());

    io_thread_ = std::thread([this] {
      BOOST_LOG_TRIVIAL(debug) << "io_context running...";
      io_ctx_->run();
      BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
    });
  }

  void TearDown() override {
    work_guard_.reset();
    io_ctx_->stop();
    if (io_thread_.joinable()) {
      io_thread_.join();
    }
  }

 protected:
  std::shared_ptr<asio::io_context> const io_ctx_{
      std::make_shared<asio::io_context>()};
  std::thread io_thread_;
  std::unique_ptr<
      asio::executor_work_guard<boost::asio::io_context::executor_type>>
      work_guard_;
};

TEST_F(TestNetworkTransport, TestUdpSingleSendAndReceive) {
  EXPECT_FALSE(io_ctx_->stopped());
  asio::ip::udp::endpoint rcvr_endpoint(
      asio::ip::address::from_string(TEST_IPV4_ADDR), TEST_PORT_NUM);

  auto string_serializer = std::make_shared<SimpleStringSerializer>();

  SimpleString message(string_serializer);
  size_t num_calls = 0;
  std::mutex mutex;
  std::condition_variable cv;

  auto message_cb = [&](SimpleString const& received) {
    std::lock_guard lock(mutex);
    BOOST_LOG_TRIVIAL(debug)
        << "Received message: \"" << received.entity() << "\"";
    EXPECT_EQ(received.entity(), message.entity());
    if (++num_calls == MAX_ITERS) {
      cv.notify_one();
    }
  };

  auto rcvr_strategy = std::make_shared<siotrns::UdpReceiveStrategy>(
      io_ctx_, rcvr_endpoint, SimpleString::max_blob_size);
  auto rcvr = std::make_shared<sio::Receiver<SimpleString>>(
      rcvr_strategy, string_serializer, message_cb);

  auto shared_socket = std::make_shared<asio::ip::udp::socket>(*io_ctx_);
  auto sndr_strategy =
      std::make_shared<siotrns::UdpSendStrategy>(shared_socket, rcvr_endpoint);
  auto sndr = std::make_shared<sio::Sender<SimpleString>>(sndr_strategy);

  for (int i = 0; i < MAX_ITERS; i++) {
    sndr->send(message);
  }
  {
    std::unique_lock lock(mutex);
    EXPECT_TRUE(cv.wait_for(lock, std::chrono::milliseconds(100),
                            [&] { return num_calls == MAX_ITERS; }));
  }
}

TEST_F(TestNetworkTransport, TestUdpMultipleSendAndReceive) {
  EXPECT_FALSE(io_ctx_->stopped());
  asio::ip::udp::endpoint rcvr_endpoint(
      asio::ip::address::from_string(TEST_IPV4_ADDR), TEST_PORT_NUM);

  auto string_serializer = std::make_shared<SimpleStringSerializer>();

  SimpleString message(string_serializer);
  size_t num_calls = 0;
  std::mutex mutex;
  std::condition_variable cv;

  auto message_cb = [&](SimpleString const& received) {
    std::lock_guard lock(mutex);
    BOOST_LOG_TRIVIAL(debug)
        << "Received message: \"" << received.entity() << "\"";
    EXPECT_EQ(received.entity(), message.entity());
    if (++num_calls == MAX_ITERS) {
      cv.notify_one();
    }
  };
  auto rcvr_strategy = std::make_shared<siotrns::UdpReceiveStrategy>(
      io_ctx_, rcvr_endpoint, SimpleString::max_blob_size);
  auto rcvr = std::make_shared<sio::Receiver<SimpleString>>(
      rcvr_strategy, string_serializer, message_cb);

  auto shared_socket = std::make_shared<asio::ip::udp::socket>(*io_ctx_);
  auto shared_strand =
      std::make_shared<asio::strand<asio::io_context::executor_type>>(
          io_ctx_->get_executor());
  auto sndr1_strategy = std::make_shared<siotrns::UdpSendStrategy>(
      shared_socket, rcvr_endpoint, shared_strand);
  auto sndr2_strategy = std::make_shared<siotrns::UdpSendStrategy>(
      shared_socket, rcvr_endpoint, shared_strand);
  auto sndr1 = std::make_shared<sio::Sender<SimpleString>>(sndr1_strategy);
  auto sndr2 = std::make_shared<sio::Sender<SimpleString>>(sndr2_strategy);

  for (int i = 0; i < MAX_ITERS; i++) {
    sndr1->send(message);
    sndr2->send(message);
  }
  {
    std::unique_lock lock(mutex);
    EXPECT_TRUE(cv.wait_for(lock, std::chrono::milliseconds(100),
                            [&] { return num_calls == 2 * MAX_ITERS; }));
  }
}

TEST_F(TestNetworkTransport, TestTcpSendAndReceive) {
  EXPECT_FALSE(io_ctx_->stopped());
  asio::ip::tcp::endpoint rcvr_endpoint(
      asio::ip::address::from_string(TEST_IPV4_ADDR), TEST_PORT_NUM);

  auto string_serializer = std::make_shared<SimpleStringSerializer>();

  SimpleString message(string_serializer);
  size_t num_calls = 0;
  std::mutex mutex;
  std::condition_variable cv;

  auto message_cb = [&](SimpleString const& received) {
    std::lock_guard lock(mutex);
    BOOST_LOG_TRIVIAL(debug)
        << "Received message: \"" << received.entity() << "\"";
    EXPECT_EQ(received.entity(), message.entity());
    if (++num_calls == MAX_ITERS) {
      cv.notify_one();
    }
  };

  auto rcvr_strategy = std::make_shared<siotrns::TcpReceiveStrategy>(
      io_ctx_, rcvr_endpoint, SimpleString::max_blob_size);
  auto rcvr = std::make_shared<sio::Receiver<SimpleString>>(
      rcvr_strategy, string_serializer, message_cb);

  auto sndr_strategy =
      std::make_shared<siotrns::TcpSendStrategy>(io_ctx_, rcvr_endpoint);
  auto sndr = std::make_shared<sio::Sender<SimpleString>>(sndr_strategy);

  for (int i = 0; i < MAX_ITERS; i++) {
    sndr->send(message);
  }
  {
    std::unique_lock lock(mutex);
    EXPECT_TRUE(cv.wait_for(lock, std::chrono::milliseconds(100),
                            [&] { return num_calls == MAX_ITERS; }));
  }
}

TEST_F(TestNetworkTransport, TestTlsSendAndReceive) {
  EXPECT_FALSE(io_ctx_->stopped());
  asio::ip::tcp::endpoint rcvr_endpoint(
      asio::ip::address::from_string(TEST_IPV4_ADDR), TEST_PORT_NUM);

  auto string_serializer = std::make_shared<SimpleStringSerializer>();

  siotrns::TlsConfig rcvr_tls_config{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};

  SimpleString message(string_serializer);
  size_t num_calls = 0;
  std::mutex mutex;
  std::condition_variable cv;

  auto message_cb = [&](SimpleString const& received) {
    std::lock_guard lock(mutex);
    BOOST_LOG_TRIVIAL(debug)
        << "Received message: \"" << received.entity() << "\"";
    EXPECT_EQ(received.entity(), message.entity());
    if (++num_calls == MAX_ITERS) {
      cv.notify_one();
    }
  };

  auto rcvr_strategy = std::make_shared<siotrns::TlsReceiveStrategy>(
      io_ctx_, rcvr_tls_config, rcvr_endpoint, SimpleString::max_blob_size);
  auto rcvr = std::make_shared<sio::Receiver<SimpleString>>(
      rcvr_strategy, string_serializer, message_cb);

  siotrns::TlsConfig sndr_tls_config{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};

  auto sndr_strategy = std::make_shared<siotrns::TlsSendStrategy>(
      io_ctx_, sndr_tls_config, rcvr_endpoint);
  auto sndr = std::make_shared<sio::Sender<SimpleString>>(sndr_strategy);

  for (int i = 0; i < MAX_ITERS; i++) {
    sndr->send(message);
  }
  {
    std::unique_lock lock(mutex);
    EXPECT_TRUE(cv.wait_for(lock, std::chrono::milliseconds(100),
                            [&] { return num_calls == MAX_ITERS; }));
  }
}

// NOLINTBEGIN [bugprone-exception-escape]
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  init_logger();
  return RUN_ALL_TESTS();
}
// NOLINTEND [bugprone-exception-escape]
