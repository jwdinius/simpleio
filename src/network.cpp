#include <boost/log/trivial.hpp>
#include "taktile/functions.hpp"
#include "taktile/io.hpp"

namespace taktile {

const char* TransportClosed::what() const noexcept {
  return "Transport closed";
}

DatagramStream::DatagramStream(boost::asio::io_context& io_context, boost::asio::ip::udp::socket socket)
: io_context_(io_context), socket_(std::move(socket)) { start_receive(); }

DatagramStream::~DatagramStream() { close(); }

void DatagramStream::close() {
    socket_.close();
}

boost::asio::ip::udp::endpoint DatagramStream::sockname() const {
    return socket_.local_endpoint();
}

boost::asio::ip::udp::endpoint DatagramStream::peername() const {
    return socket_.remote_endpoint();
}

void DatagramStream::start_receive() {
    auto buffer = std::make_shared<std::vector<uint8_t>>(1024);
    auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();

    socket_.async_receive_from(
        boost::asio::buffer(*buffer), *remote_endpoint,
        [this, buffer, remote_endpoint](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                BOOST_LOG_TRIVIAL(debug) << "Received " << length << " bytes";
                buffer->resize(length);
                recv_queue_.push({ *buffer, *remote_endpoint });
                start_receive();
            } else {
                BOOST_LOG_TRIVIAL(error) << "Error: " << ec.message();
                exc_queue_.push(std::make_exception_ptr(std::runtime_error(ec.message())));
            }
        });
    BOOST_LOG_TRIVIAL(debug) << "Started receive";
}

std::pair<std::vector<uint8_t>, boost::asio::ip::udp::endpoint> DatagramStream::recv() {
    return recv_queue_.wait_and_pop();
}

DatagramServer::DatagramServer(boost::asio::io_context& io_context, boost::asio::ip::udp::socket socket)
: DatagramStream(io_context, std::move(socket)) {}

void DatagramServer::send(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& addr) {
    socket_.async_send_to(boost::asio::buffer(data), addr, [](boost::system::error_code, std::size_t) {});
}

DatagramClient::DatagramClient(boost::asio::io_context& io_context, boost::asio::ip::udp::socket socket)
: DatagramStream(io_context, std::move(socket))
{
    if (!socket_.is_open()) {
        BOOST_LOG_TRIVIAL(debug) << "Opening socket";
        socket_.open(boost::asio::ip::udp::v4());
    }
}

void DatagramClient::send(const std::vector<uint8_t>& data) {
    socket_.async_send(boost::asio::buffer(data), [](boost::system::error_code, std::size_t) {});
}

void DatagramClient::send(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& dest) {
    BOOST_LOG_TRIVIAL(debug) << "Calling async_send_to() to " 
              << dest.address().to_string() << ":" << dest.port();
    socket_.async_send_to(boost::asio::buffer(data), dest,
        [](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (ec) {
                BOOST_LOG_TRIVIAL(debug) << "Send failed: " << ec.message() << ".";
            } else {
                BOOST_LOG_TRIVIAL(info) << "Sent " << bytes_transferred << " bytes" << ".";
            }
        });
}

Protocol::Protocol(std::shared_ptr<DatagramStream> stream) : stream_(stream) {}

void Protocol::datagram_received(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& addr) {
    stream_->recv_queue_.push({ data, addr });
}

void Protocol::error_received(std::exception_ptr e) {
    stream_->exc_queue_.push(e);
}

} // namespace taktile