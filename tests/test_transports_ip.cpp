#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/attributes/clock.hpp>
#include <thread>

#include "simpleio/transports/tcp.hpp"
#include "simpleio/transports/tls.hpp"
#include "simpleio/transports/udp.hpp"

#include "certs_path.h"

using namespace boost::asio;
using namespace boost::log;
namespace sio = simpleio;
namespace siotrns = simpleio::transports;

void init_logger()
{
    core::get()->add_global_attribute("TimeStamp", attributes::local_clock());
    add_console_log(std::clog, keywords::format = "[%TimeStamp%] [%Severity%] %Message%");
    core::get()->set_filter(trivial::severity >= trivial::debug);
}

class SimpleStringSerializer : public sio::SerializationStrategy<std::string>
{
public:
    std::vector<std::byte> serialize(std::string const& entity) override
    {
        std::vector<std::byte> blob(entity.size());
        std::memcpy(blob.data(), entity.data(), entity.size());
        return blob;
    }

    std::string deserialize(std::vector<std::byte> const& blob) override
    {
        return std::string(reinterpret_cast<char const*>(blob.data()), blob.size());
    }
};

class SimpleString : public sio::Message<std::string, 64>
{
public:
    SimpleString(std::shared_ptr<sio::SerializationStrategy<std::string>> serializer)
    : sio::Message<std::string, 64>(std::string("Hello, World!"), serializer)
    {
    }

    SimpleString(std::vector<std::byte> const& blob,
        std::shared_ptr<sio::SerializationStrategy<std::string>> serializer)
    : sio::Message<std::string, 64>(blob, serializer)
    {
    }
};

class TestNetworkTransport : public ::testing::Test {

    void SetUp() override
    {
        BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
        // Prevent io_context from exiting when idle
        work_guard = std::make_unique<executor_work_guard<io_context::executor_type>>(
            io.get_executor());

        io_thread = std::thread(
            [this] {
                BOOST_LOG_TRIVIAL(debug) << "io_context running...";
                io.run();
                BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
            });
    }

    void TearDown() override
    {
        work_guard.reset();
        io.stop();
        if (io_thread.joinable()) {
            io_thread.join();
        }
    }

protected:
    io_context io;
    std::thread io_thread;
    std::unique_ptr<executor_work_guard<boost::asio::io_context::executor_type>> work_guard;
};

TEST_F(TestNetworkTransport, TestUdpSendAndReceive)
{
    EXPECT_FALSE(io.stopped());
    ip::udp::endpoint rcvr_endpoint(ip::address::from_string("127.0.0.1"), 12345);
    
    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    auto rcvr_strategy = std::make_shared<siotrns::UdpReceiveStrategy>(
        io, rcvr_endpoint, SimpleString::max_blob_size);
    auto rcvr = std::make_shared<sio::Receiver>(rcvr_strategy); 
    
    auto sndr_strategy = std::make_shared<siotrns::UdpSendStrategy>(
        io, rcvr_endpoint);
    auto sndr = std::make_shared<sio::Sender<SimpleString>>(sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->extract_message<SimpleString>(string_serializer);
        EXPECT_EQ(received.entity(), message.entity());
    }
}

TEST_F(TestNetworkTransport, TestTcpSendAndReceive) {
    EXPECT_FALSE(io.stopped());
    ip::tcp::endpoint rcvr_endpoint(ip::address::from_string("127.0.0.1"), 54321);

    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    auto rcvr_strategy = std::make_shared<siotrns::TcpReceiveStrategy>(
        io, rcvr_endpoint, SimpleString::max_blob_size);
    auto rcvr = std::make_shared<sio::Receiver>(rcvr_strategy); 

    auto sndr_strategy = std::make_shared<siotrns::TcpSendStrategy>(
        io, rcvr_endpoint);
    auto sndr = std::make_shared<sio::Sender<SimpleString>>(
        sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->extract_message<SimpleString>(
            string_serializer);
        EXPECT_EQ(received.entity(), message.entity());
    }
}

TEST_F(TestNetworkTransport, TestTlsSendAndReceive) {
    EXPECT_FALSE(io.stopped());
    ip::tcp::endpoint rcvr_endpoint(ip::address::from_string("127.0.0.1"), 54321);

    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    siotrns::TlsConfig rcvr_tls_config
    {
        .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
        .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
        .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"
    };

    auto rcvr_strategy = std::make_shared<siotrns::TlsReceiveStrategy>(
        io, rcvr_tls_config, rcvr_endpoint, SimpleString::max_blob_size);
    auto rcvr = std::make_shared<sio::Receiver>(rcvr_strategy); 
 
    siotrns::TlsConfig sndr_tls_config
    {
        .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
        .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
        .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"
    };

    auto sndr_strategy = std::make_shared<siotrns::TlsSendStrategy>(
        io, sndr_tls_config, rcvr_endpoint);
    auto sndr = std::make_shared<sio::Sender<SimpleString>>(sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->extract_message<SimpleString>(string_serializer);
        EXPECT_EQ(received.entity(), message.entity());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    init_logger();
    return RUN_ALL_TESTS();
}
