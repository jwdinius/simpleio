#include <boost/log/trivial.hpp>

#include "simpleio/transports/tcp.hpp"

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::TcpSendStrategy::TcpSendStrategy(
    boost::asio::io_context& io,
    boost::asio::ip::tcp::endpoint const& remote_endpoint)
: socket_(io)
, remote_endpoint_(remote_endpoint)
{
}

siotrns::TcpSendStrategy::~TcpSendStrategy()
{
    socket_.close();
}

void siotrns::TcpSendStrategy::send(std::vector<std::byte> const& blob)
{
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

void siotrns::TcpSendStrategy::connect()
{
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

siotrns::TcpReceiveStrategy::TcpReceiveStrategy(
    boost::asio::io_context& io,
    boost::asio::ip::tcp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
: acceptor_(io, local_endpoint)
, max_blob_size_(max_blob_size)
, sio::ReceiveStrategy()
{
    start_accepting();
}

siotrns::TcpReceiveStrategy::~TcpReceiveStrategy()
{
    acceptor_.close();
}

void siotrns::TcpReceiveStrategy::start_accepting()
{
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

void siotrns::TcpReceiveStrategy::start_receiving(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
{
    auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);

    boost::asio::async_read(*socket, boost::asio::buffer(*buffer),
        [this, buffer, socket](boost::system::error_code ec, size_t bytes_recvd) {
            // We expect the client to close the connection after sending a message
            // i.e., "Open-Squirt-Close" for the simplest case
            if (ec == boost::asio::error::eof && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes.";
                buffer->resize(bytes_recvd);
                this->blob_queue_.push(std::move(*buffer));
                start_receiving(socket);
            } else {
                BOOST_LOG_TRIVIAL(error) << "Error receiving data: " << ec.message();
            }
        });
}
