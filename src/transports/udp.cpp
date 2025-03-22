#include <boost/log/trivial.hpp>

#include "simpleio/transports/udp.hpp"

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::UdpSendStrategy::UdpSendStrategy(
    boost::asio::io_context& io,
    boost::asio::ip::udp::endpoint const& remote_endpoint)
: socket_(io)
, remote_endpoint_(remote_endpoint)
{
    BOOST_LOG_TRIVIAL(debug) << "Configuring SendStrategy to " << remote_endpoint_;
}

void siotrns::UdpSendStrategy::send(const std::vector<std::byte>& blob)
{
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

siotrns::UdpReceiveStrategy::UdpReceiveStrategy(
    boost::asio::io_context& io,
    boost::asio::ip::udp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
: socket_(io, local_endpoint)
, max_blob_size_(max_blob_size)
, ReceiveStrategy()
{
    BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_.local_endpoint();
    start_receiving();
}
    
siotrns::UdpReceiveStrategy::~UdpReceiveStrategy() { socket_.close(); }
    
void siotrns::UdpReceiveStrategy::start_receiving()
{
    auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);
    auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();
    
    socket_.async_receive_from(boost::asio::buffer(*buffer), *remote_endpoint,
        [this, buffer, remote_endpoint](boost::system::error_code ec, size_t bytes_recvd) {
            if (!ec && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes from " << *remote_endpoint;
                buffer->resize(bytes_recvd);
                this->blob_queue_.push(std::move(*buffer));
                start_receiving();
            } else {
                // Handle the error
                BOOST_LOG_TRIVIAL(error) << "Error receiving data: " << ec.message();
            }
        });
    BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
}
