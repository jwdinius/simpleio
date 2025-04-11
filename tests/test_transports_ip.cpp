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
    io_worker_ = std::make_shared<siotrns::ip::IoWorker>();
  }

  void TearDown() override {
    io_worker_.reset();
  }

 protected:
  std::shared_ptr<siotrns::ip::IoWorker> io_worker_;
};

TEST_F(TestNetworkTransport, TestUdpSingleSendAndReceive) {
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

  auto rcvr = siotrns::ip::make_receiver<SimpleString, SimpleStringSerializer>(
      io_worker_, siotrns::ip::Scheme::UDP, TEST_IPV4_ADDR, TEST_PORT_NUM,
      message_cb);
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, TEST_IPV4_ADDR, TEST_PORT_NUM);

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

  auto rcvr = siotrns::ip::make_receiver<SimpleString, SimpleStringSerializer>(
      io_worker_, siotrns::ip::Scheme::UDP, TEST_IPV4_ADDR, TEST_PORT_NUM,
      message_cb);
  auto sndr1 = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, TEST_IPV4_ADDR, TEST_PORT_NUM);
  auto sndr2 = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::UDP, TEST_IPV4_ADDR, TEST_PORT_NUM);

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

  auto rcvr = siotrns::ip::make_receiver<SimpleString, SimpleStringSerializer>(
      io_worker_, siotrns::ip::Scheme::TCP, TEST_IPV4_ADDR, TEST_PORT_NUM,
      message_cb);
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TCP, TEST_IPV4_ADDR, TEST_PORT_NUM);

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

  siotrns::ip::TlsConfig rcvr_tls_config{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"};
  auto rcvr = siotrns::ip::make_receiver<SimpleString, SimpleStringSerializer>(
      io_worker_, siotrns::ip::Scheme::TLS, TEST_IPV4_ADDR, TEST_PORT_NUM,
      message_cb, rcvr_tls_config);

  siotrns::ip::TlsConfig sndr_tls_config{
      .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
      .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
      .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"};
  auto sndr = siotrns::ip::make_sender<SimpleString>(
      io_worker_, siotrns::ip::Scheme::TLS, TEST_IPV4_ADDR, TEST_PORT_NUM,
      sndr_tls_config);

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
