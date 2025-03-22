#pragma once
#include <boost/asio.hpp>

#include "simpleio/transport.hpp"

namespace simpleio {
namespace transports {

/// @brief Strategy for sending messages over TCP
class TcpSendStrategy : public SendStrategy
{
public:

    /// @brief Construct from a shared io_context and a remote endpoint.
    /// @param io, (reference to) the shared io_context. 
    /// @param remote_endpoint, the remote endpoint to send to. 
    explicit TcpSendStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::endpoint const& remote_endpoint);

    /// @brief Destructor
    ~TcpSendStrategy();

    /// @brief Send a byte vector.
    /// @param blob, the byte vector to send. 
    void send(std::vector<std::byte> const& blob) override;

private:
    void connect();

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::endpoint remote_endpoint_;
};


/// @brief Strategy for receiving messages over TCP
class TcpReceiveStrategy : public ReceiveStrategy
{
public:

    /// @brief Construct from a shared io_context, a local endpoint, and a maximum blob size.
    /// @param io, (reference to) the shared io_context.
    /// @param local_endpoint, local endpoint to listen on. 
    /// @param max_blob_size, maximum size of allocated receive buffer. 
    explicit TcpReceiveStrategy(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::endpoint const& local_endpoint,
        size_t const& max_blob_size);

    /// @brief Destructor
    ~TcpReceiveStrategy();

private:
    void start_accepting();
    void start_receiving(std::shared_ptr<boost::asio::ip::tcp::socket> socket);

    boost::asio::ip::tcp::acceptor acceptor_;
    size_t const max_blob_size_;
};

} // namespace network_transport
} // namespace simpleio