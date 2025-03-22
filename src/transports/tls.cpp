#include <sstream>

#include <boost/log/trivial.hpp>

#include "simpleio/transports/tls.hpp"

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::TlsSendStrategy::TlsSendStrategy(
    boost::asio::io_context& io,
    siotrns::TlsConfig const& tls_config,
    boost::asio::ip::tcp::endpoint const& remote_endpoint)
: io_ctx_(io)
, remote_endpoint_(remote_endpoint)
, ssl_ctx_(boost::asio::ssl::context::tlsv13)
, socket_(std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_ctx_, ssl_ctx_))
{
    try {
        ssl_ctx_.load_verify_file(tls_config.ca_file.string());
        ssl_ctx_.use_certificate_chain_file(tls_config.cert_file.string());
        ssl_ctx_.use_private_key_file(
            tls_config.key_file.string(), boost::asio::ssl::context::pem);
    } catch (std::exception& e) {
        std::ostringstream error_stream;
        error_stream << "Error setting up TLSv1.3 context: " << e.what();
        BOOST_LOG_TRIVIAL(error) << error_stream.str();
        throw std::runtime_error(error_stream.str());
    }
}

void siotrns::TlsSendStrategy::send(const std::vector<std::byte>& blob)
{
    connect();
    boost::asio::async_write(*socket_, boost::asio::buffer(blob),
        [this](boost::system::error_code ec, std::size_t bytes_sent) {
            if (!ec) {
                BOOST_LOG_TRIVIAL(debug) << "Sent " << bytes_sent << " bytes securely to " << remote_endpoint_;
            } else {
                BOOST_LOG_TRIVIAL(error) << "Error sending data: " << ec.message();
            }
        });
    close();
}

void siotrns::TlsSendStrategy::connect()
{
    BOOST_LOG_TRIVIAL(debug) << "Connecting to " << remote_endpoint_;
    // Reset the socket to reuse the existing SSL context
    socket_ = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_ctx_, ssl_ctx_);
    socket_->lowest_layer().open(boost::asio::ip::tcp::v4());

    // Attempt to establish a new connection
    boost::system::error_code ec;
    socket_->lowest_layer().connect(remote_endpoint_, ec);
    if (!ec) {
        BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;

        // Perform TLS handshake
        socket_->handshake(boost::asio::ssl::stream_base::client, ec);
        if (!ec) {
            BOOST_LOG_TRIVIAL(debug) << "TLSv1.3 Handshake successful!";
        } else {
            BOOST_LOG_TRIVIAL(error) << "TLSv1.3 Handshake failed: " << ec.message();
        }
    } else {
        BOOST_LOG_TRIVIAL(error) << "Failed to connect: " << ec.message();
    }
    BOOST_LOG_TRIVIAL(debug) << "Connected to " << remote_endpoint_;
}

void siotrns::TlsSendStrategy::close()
{
    BOOST_LOG_TRIVIAL(debug) << "Closing connection to " << remote_endpoint_;
    boost::system::error_code ec;
    socket_->shutdown(ec);
    socket_.reset();
    BOOST_LOG_TRIVIAL(debug) << "Closed connection to " << remote_endpoint_;
}

siotrns::TlsReceiveStrategy::TlsReceiveStrategy(
    boost::asio::io_context& io,
    TlsConfig const& tls_config,
    boost::asio::ip::tcp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
: acceptor_(io, local_endpoint)
, ssl_ctx_(boost::asio::ssl::context::tlsv13)
, max_blob_size_(max_blob_size)
, sio::ReceiveStrategy()
{
    try {
        ssl_ctx_.load_verify_file(tls_config.ca_file.string());
        ssl_ctx_.use_certificate_chain_file(tls_config.cert_file.string());
        ssl_ctx_.use_private_key_file(
            tls_config.key_file.string(), boost::asio::ssl::context::pem);
    } catch (std::exception& e) {
        std::ostringstream error_stream;
        error_stream << "Error setting up TLSv1.3 context: " << e.what();
        BOOST_LOG_TRIVIAL(error) << error_stream.str();
        throw std::runtime_error(error_stream.str());
    }
    
    start_accepting();
}

siotrns::TlsReceiveStrategy::~TlsReceiveStrategy()
{
    acceptor_.close();
}

void siotrns::TlsReceiveStrategy::start_accepting()
{
    auto socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(acceptor_.get_executor(), ssl_ctx_);
    acceptor_.async_accept(socket->lowest_layer(), [this, socket](boost::system::error_code ec) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(info) << "Accepted secure connection from " << socket->lowest_layer().remote_endpoint();
            start_handshake(socket);
        } else {
            BOOST_LOG_TRIVIAL(error) << "Accept failed: " << ec.message();
        }
        start_accepting();  // Keep listening for new connections
    });
}

void siotrns::TlsReceiveStrategy::start_handshake(std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket)
{
    socket->async_handshake(boost::asio::ssl::stream_base::server, [this, socket](boost::system::error_code ec) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(debug) << "TLSv1.3 handshake successful!";
            start_receiving(socket);
        } else {
            BOOST_LOG_TRIVIAL(error) << "TLSv1.3 handshake failed: " << ec.message();
        }
    });
}

void siotrns::TlsReceiveStrategy::start_receiving(std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket)
{
    auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);

    boost::asio::async_read(*socket, boost::asio::buffer(*buffer),
        [this, buffer, socket](boost::system::error_code ec, size_t bytes_recvd) {
            if (ec == boost::asio::error::eof && bytes_recvd > 0) {
                BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd << " bytes securely.";
                buffer->resize(bytes_recvd);
                this->blob_queue_.push(std::move(*buffer));
                start_receiving(socket);
            } else {
                BOOST_LOG_TRIVIAL(error) << "Error receiving data: " << ec.message();
            }
        });
}
