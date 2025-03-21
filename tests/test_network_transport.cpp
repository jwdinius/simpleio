#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/attributes/clock.hpp>
#include <thread>

#include "simpleio/network_transport/tcp.hpp"
#include "simpleio/network_transport/tls.hpp"
#include "simpleio/network_transport/udp.hpp"

#include "certs_path.h"

using namespace boost::asio;
using namespace std::chrono_literals;

void init_logger() {
    boost::log::core::get()->add_global_attribute("TimeStamp", boost::log::attributes::local_clock());
    boost::log::add_console_log(std::clog, boost::log::keywords::format = "[%TimeStamp%] [%Severity%] %Message%");
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
}

class SimpleStringSerializer : public simpleio::SerializationStrategy<std::string> {
public:
    std::vector<std::byte> serialize(std::string const& entity) override {
        std::vector<std::byte> blob(entity.size());
        std::memcpy(blob.data(), entity.data(), entity.size());
        return blob;
    }

    std::string deserialize(std::vector<std::byte> const& blob) override {
        return std::string(reinterpret_cast<char const*>(blob.data()), blob.size());
    }
};

class SimpleString : public simpleio::Message<std::string, 64> { 
public:
    SimpleString(std::shared_ptr<simpleio::SerializationStrategy<std::string>> serializer)
    : simpleio::Message<std::string, 64>(std::string("Hello, World!"), serializer)
    {}

    SimpleString(std::vector<std::byte> const& blob, std::shared_ptr<simpleio::SerializationStrategy<std::string>> serializer)
    : simpleio::Message<std::string, 64>(blob, serializer)
    {}
};
class TestNetworkTransport : public ::testing::Test {

    void SetUp() override {
        BOOST_LOG_TRIVIAL(debug) << "Starting io_context thread";
        // Prevent io_context from exiting when idle
        work_guard = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(io.get_executor());

        io_thread = std::thread([this] { 
            BOOST_LOG_TRIVIAL(debug) << "io_context running...";
            io.run();
            BOOST_LOG_TRIVIAL(debug) << "io_context stopped.";
        });
    }

    void TearDown() override {
        work_guard.reset();
        io.stop();
        if (io_thread.joinable()) {
            io_thread.join();
        }
    }

    protected:
    io_context io;
    std::thread io_thread;
    std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard;
};

TEST_F(TestNetworkTransport, TestUdpSendAndReceive) {
    EXPECT_FALSE(io.stopped());
    boost::asio::ip::udp::endpoint rcvr_endpoint(
        boost::asio::ip::address::from_string("127.0.0.1"), 12345);
    
    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    auto rcvr_strategy = std::make_shared<simpleio::network_transport::UdpReceiveStrategy<SimpleString>>(
        io, rcvr_endpoint, string_serializer);
    auto rcvr = std::make_shared<simpleio::Receiver<SimpleString>>(rcvr_strategy); 
    
    auto sndr_strategy = std::make_shared<simpleio::network_transport::UdpSendStrategy>(
        io, rcvr_endpoint);
    auto sndr = std::make_shared<simpleio::Sender<SimpleString>>(sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->pop_message();
        EXPECT_EQ(received.entity(), message.entity());
    }
}

TEST_F(TestNetworkTransport, TestTcpSendAndReceive) {
    EXPECT_FALSE(io.stopped());
    boost::asio::ip::tcp::endpoint rcvr_endpoint(
        boost::asio::ip::address::from_string("127.0.0.1"), 54321);

    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    auto rcvr_strategy = std::make_shared<simpleio::network_transport::TcpReceiveStrategy<SimpleString>>(
        io, rcvr_endpoint, string_serializer);
    auto rcvr = std::make_shared<simpleio::Receiver<SimpleString>>(rcvr_strategy); 

    auto sndr_strategy = std::make_shared<simpleio::network_transport::TcpSendStrategy>(
        io, rcvr_endpoint);
    auto sndr = std::make_shared<simpleio::Sender<SimpleString>>(sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->pop_message();
        EXPECT_EQ(received.entity(), message.entity());
    }
}

TEST_F(TestNetworkTransport, TestTlsSendAndReceive) {
    EXPECT_FALSE(io.stopped());
    boost::asio::ip::tcp::endpoint rcvr_endpoint(
        boost::asio::ip::address::from_string("127.0.0.1"), 54321);

    auto string_serializer = std::make_shared<SimpleStringSerializer>();
    
    simpleio::network_transport::TlsConfig rcvr_tls_config
    {
        .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
        .cert_file = std::filesystem::path(CERTS_PATH) / "receiver.crt",
        .key_file = std::filesystem::path(CERTS_PATH) / "private/receiver.key"
    };

    auto rcvr_strategy = std::make_shared<simpleio::network_transport::TlsReceiveStrategy<SimpleString>>(
        io, rcvr_tls_config, rcvr_endpoint, string_serializer);
    auto rcvr = std::make_shared<simpleio::Receiver<SimpleString>>(rcvr_strategy); 
 
    simpleio::network_transport::TlsConfig sndr_tls_config
    {
        .ca_file = std::filesystem::path(CERTS_PATH) / "ca.crt",
        .cert_file = std::filesystem::path(CERTS_PATH) / "sender.crt",
        .key_file = std::filesystem::path(CERTS_PATH) / "private/sender.key"
    };

    auto sndr_strategy = std::make_shared<simpleio::network_transport::TlsSendStrategy>(
        io, sndr_tls_config, rcvr_endpoint);
    auto sndr = std::make_shared<simpleio::Sender<SimpleString>>(sndr_strategy);

    auto message = SimpleString(string_serializer);
    
    for (int i = 0; i < 10; i++) {
        sndr->send(message);
        auto received = rcvr->pop_message();
        EXPECT_EQ(received.entity(), message.entity());
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    init_logger();
    return RUN_ALL_TESTS();
}