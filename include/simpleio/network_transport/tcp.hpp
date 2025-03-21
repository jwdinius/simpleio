#pragma once
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>

#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"
#include "simpleio/transport.hpp"

namespace simpleio {
namespace network_transport {

class TcpSendStrategy : public SendStrategy {
public:
    explicit TcpSendStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::endpoint const& remote_endpoint)
    : socket_(io)
    , remote_endpoint_(remote_endpoint)
    {
    }

    ~TcpSendStrategy() {
        socket_.close();
    }

    void send(const std::vector<std::byte>& blob) override {
        connect();
        boost::asio::async_write(socket_, boost::asio::buffer(blob),
            [this](boost::system::error_code ec, std::size_t bytes_sent) {
                if (!ec) {
                    BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes " << " to " << remote_endpoint_;
                } else {
                    BOOST_LOG_TRIVIAL(error) << "Error sending data: " << ec.message();
                }
            });
        socket_.close();
    }

protected:
    void connect() {
        BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
        boost::system::error_code ec;
        socket_.connect(remote_endpoint_, ec);
        if (!ec) {
            BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
        } else {
            BOOST_LOG_TRIVIAL(error) << "Failed to connect: " << ec.message();
        }
        BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
    }

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
};


template <typename MessageType>
class TcpReceiveStrategy : public ReceiveStrategy<MessageType> {
public:
    TcpReceiveStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::endpoint const& local_endpoint,
        std::shared_ptr<SerializationStrategy<typename MessageType::entity_type>> serializer)
    : acceptor_(io, local_endpoint)
    , ReceiveStrategy<MessageType>(serializer)
    {
        start_accepting();
    }

    ~TcpReceiveStrategy() {
        acceptor_.close();
    }

    void start_accepting() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*socket, [this, socket](boost::system::error_code ec) {
            if (!ec) {
                BOOST_LOG_TRIVIAL(info) << "Accepted connection from peer at " << socket->remote_endpoint();
                start_receiving(socket);
            } else {
                BOOST_LOG_TRIVIAL(error) << "Accept failed: " << ec.message();
            }
            start_accepting();
        });
    }

    void start_receiving(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        auto buffer = std::make_shared<std::vector<std::byte>>(MessageType::max_blob_size);

        boost::asio::async_read(*socket, boost::asio::buffer(*buffer),
            [this, buffer, socket](boost::system::error_code ec, std::size_t bytes_recvd) {
                // We expect the client to close the connection after sending a message
                // i.e., "Open-Squirt-Close" for the simplest case
                if (ec == boost::asio::error::eof && bytes_recvd > 0) {
                    BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes.";
                    buffer->resize(bytes_recvd);
                    try {
                        auto message = MessageType(std::move(*buffer), this->serializer());
                        msg_queue_.push(message);
                    } catch (std::exception& e) {
                        BOOST_LOG_TRIVIAL(error) << "Error framing message: " << e.what();
                    }
                    start_receiving(socket);
                } else {
                    BOOST_LOG_TRIVIAL(error) << "Error receiving data: " << ec.message();
                }
            });
    }

    MessageType pop_message() override {
        return msg_queue_.wait_and_pop();
    }

protected:
    boost::asio::ip::tcp::acceptor acceptor_;
    AsyncQueue<MessageType> msg_queue_;
};

} // namespace network_transport
} // namespace simpleio