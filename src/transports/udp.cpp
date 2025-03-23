// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/udp.hpp"

#include <boost/log/trivial.hpp>
#include <memory>
#include <utility>
#include <vector>

namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::UdpSendStrategy::UdpSendStrategy(
    std::shared_ptr<boost::asio::io_context> const& io_ctx,
    boost::asio::ip::udp::endpoint remote_endpoint)
    : socket_(*io_ctx), remote_endpoint_(std::move(remote_endpoint)) {
  BOOST_LOG_TRIVIAL(debug) << "Configuring SendStrategy to "
                           << remote_endpoint_;
}

void siotrns::UdpSendStrategy::send(std::vector<std::byte> const& blob) {
  socket_.open(boost::asio::ip::udp::v4());
  socket_.async_send_to(
      boost::asio::buffer(blob), remote_endpoint_,
      [this](boost::system::error_code err_code, std::size_t bytes_sent) {
        if (!err_code) {
          BOOST_LOG_TRIVIAL(debug)
              << "Sent " << bytes_sent << " bytes to " << remote_endpoint_;
        } else {
          BOOST_LOG_TRIVIAL(error)
              << "Error sending data: " << err_code.message();
        }
      });
  socket_.close();
}

siotrns::UdpReceiveStrategy::UdpReceiveStrategy(
    std::shared_ptr<boost::asio::io_context> const& io_ctx,
    boost::asio::ip::udp::endpoint const& local_endpoint,
    size_t const& max_blob_size)
    : socket_(*io_ctx, local_endpoint), max_blob_size_(max_blob_size) {
  BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_.local_endpoint();
  start_receiving();
}

siotrns::UdpReceiveStrategy::~UdpReceiveStrategy() {
  try {
    socket_.close();
  } catch (std::exception const& e) {
    BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
  }
}

void siotrns::UdpReceiveStrategy::start_receiving() {
  auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);
  auto remote_endpoint = std::make_shared<boost::asio::ip::udp::endpoint>();

  socket_.async_receive_from(
      boost::asio::buffer(*buffer), *remote_endpoint,
      [this, buffer, remote_endpoint](boost::system::error_code err_code,
                                      size_t bytes_recvd) {
        if (!err_code && bytes_recvd > 0) {
          BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd
                                   << " bytes from " << *remote_endpoint;
          buffer->resize(bytes_recvd);
          this->blob_queue_.push(std::move(*buffer));
          start_receiving();
        } else {
          // Handle the error
          BOOST_LOG_TRIVIAL(error)
              << "Error receiving data: " << err_code.message();
        }
      });
  BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
}
