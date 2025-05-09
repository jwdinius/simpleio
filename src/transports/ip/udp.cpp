// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include "simpleio/transports/ip/udp.hpp"

#include <boost/log/trivial.hpp>
#include <memory>
#include <utility>
#include <vector>

namespace ba = boost::asio;
namespace sio = simpleio;
namespace siotrns = simpleio::transports;

siotrns::ip::UdpSendStrategy::UdpSendStrategy(
    std::shared_ptr<ba::ip::udp::socket> socket,
    ba::ip::udp::endpoint remote_endpoint)
    : socket_(std::move(socket)), remote_endpoint_(std::move(remote_endpoint)) {
  BOOST_LOG_TRIVIAL(debug) << "Configuring the socket to send to "
                           << remote_endpoint_;
  if (!socket_->is_open()) {
    socket_->open(remote_endpoint_.protocol());
  }
  BOOST_LOG_TRIVIAL(debug) << "Socket is open? " << socket_->is_open()
                           << " Local endpoint: " << socket_->local_endpoint();
}

siotrns::ip::UdpSendStrategy::~UdpSendStrategy() {
  try {
    if (socket_->is_open()) {
      socket_->close();
    }
  } catch (std::exception const& e) {
    BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
  }
}

void siotrns::ip::UdpSendStrategy::send(std::vector<std::byte> const& blob) {
  auto send_fn = [this](boost::system::error_code err_code,
                        std::size_t bytes_sent) {
    if (!err_code) {
      BOOST_LOG_TRIVIAL(debug)
          << "Sent " << bytes_sent << " bytes to " << remote_endpoint_;
    } else {
      BOOST_LOG_TRIVIAL(error) << "Error sending data: " << err_code.message();
    }
  };
  socket_->async_send_to(ba::buffer(blob), remote_endpoint_, send_fn);
}

siotrns::ip::UdpReceiveStrategy::UdpReceiveStrategy(
    std::shared_ptr<ba::io_context> const& io_ctx,
    ba::ip::udp::endpoint const& local_endpoint, size_t const& max_blob_size)
    : max_blob_size_(max_blob_size) {
  socket_ = std::make_unique<ba::ip::udp::socket>(*io_ctx, local_endpoint);
  BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
  start_receiving();
}

siotrns::ip::UdpReceiveStrategy::UdpReceiveStrategy(
    std::unique_ptr<ba::ip::udp::socket> socket, size_t const& max_blob_size)
    : socket_(std::move(socket)), max_blob_size_(max_blob_size) {
  BOOST_LOG_TRIVIAL(debug) << "Listening on " << socket_->local_endpoint();
  start_receiving();
}

siotrns::ip::UdpReceiveStrategy::~UdpReceiveStrategy() {
  try {
    socket_->close();
  } catch (std::exception const& e) {
    BOOST_LOG_TRIVIAL(error) << "Exception in destructor: " << e.what();
  }
}

void siotrns::ip::UdpReceiveStrategy::start_receiving() {
  auto buffer = std::make_shared<std::vector<std::byte>>(max_blob_size_);
  auto remote_endpoint = std::make_shared<ba::ip::udp::endpoint>();

  socket_->async_receive_from(
      ba::buffer(*buffer), *remote_endpoint,
      [this, buffer, remote_endpoint](boost::system::error_code err_code,
                                      size_t bytes_recvd) {
        if (!err_code && bytes_recvd > 0) {
          BOOST_LOG_TRIVIAL(debug) << "Received " << bytes_recvd
                                   << " bytes from " << *remote_endpoint;
          buffer->resize(bytes_recvd);
          this->event_cb_(*buffer);
          start_receiving();
        } else {
          // Handle the error
          BOOST_LOG_TRIVIAL(error)
              << "Error receiving data: " << err_code.message();
        }
      });
  BOOST_LOG_TRIVIAL(debug) << "Waiting for data...";
}
