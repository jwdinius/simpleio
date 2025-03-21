#pragma once
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/log/trivial.hpp>

#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"
#include "simpleio/transport.hpp"

namespace simpleio {
namespace network_transport {

class UdpSendStrategy : public SendStrategy {
public:
    explicit UdpSendStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::udp::endpoint const& remote_endpoint)
    : socket_(io)
    , remote_endpoint_(remote_endpoint)
    {
        BOOST_LOG_TRIVIAL(debug) << "Configuring SendStrategy to " << remote_endpoint_;
    }

    void send(const std::vector<std::byte>& blob) override {
        socket_.open(boost::asio::ip::udp::v4());
        socket_.async_send_to(
            boost::asio::buffer(blob), remote_endpoint_,
            [this](boost::system::error_code ec, std::size_t bytes_sent) {
                if (!ec) {
                    BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes to " << remote_endpoint_;
                } else {
                    BOOST_LOG_TRIVIAL(error) << "Error sending data: " << ec.message();
                }
            });
        socket_.close();
    }

protected:
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
};

template <typename MessageType>
class UdpReceiveStrategy : public ReceiveStrategy<MessageType> {
public:

    UdpReceiveStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::udp::endpoint const& local_endpoint,
        std::shared_ptr<SerializationStrategy<typename MessageType::entity_type>> serializer)
    : socket_(io, local_endpoint)
    , ReceiveStrategy<MessageType>(serializer)
    {
        BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_.local_endpoint();
        start_receiving();
    }
    
    ~UdpReceiveStrategy() { socket_.close(); }

    void start_receiving()
    {
        auto buffer = std::make_shared<std::vector<std::byte>>(MessageType::max_blob_size);
        auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();
        
        socket_.async_receive_from(boost::asio::buffer(*buffer), *remote_endpoint,
            [this, buffer, remote_endpoint](boost::system::error_code ec, std::size_t bytes_recvd) {
                if (!ec && bytes_recvd > 0) {
                    BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes from " << *remote_endpoint;
                    buffer->resize(bytes_recvd);
                    try {
                        auto message = MessageType(std::move(*buffer), this->serializer());
                        msg_queue_.push(message);
                    } catch (std::exception& e) {
                        BOOST_LOG_TRIVIAL(error) << "Error framing message: " << e.what();
                    }
                    start_receiving();
                } else {
                    // Handle the error
                    BOOST_LOG_TRIVIAL(error) << "Error receiving data: " << ec.message();
                }
            });
        BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
    }
    
    MessageType pop_message() override
    {
        return msg_queue_.wait_and_pop();
    }

protected:
    boost::asio::ip::udp::socket socket_;
    AsyncQueue<MessageType> msg_queue_;
};
} // namespace network
} // namespace simpleio