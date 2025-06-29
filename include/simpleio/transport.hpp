// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "simpleio/async_queue.hpp"
#include "simpleio/message.hpp"
#include "simpleio/worker.hpp"

namespace simpleio {
/// @brief Exception thrown when a transport error occurs at runtime.
class TransportException : public std::runtime_error {
 public:
  explicit TransportException(std::string const& what)
      : std::runtime_error(what) {}
};

/// @brief Message sender
/// @details This class is responsible for sending messages of type MessageT.
/// @tparam MessageT, the type of message to send.
template <typename MessageT>
class Sender {
 public:
  using message_t = MessageT;

  /// @brief Default destructor.
  virtual ~Sender() = default;

  /// @brief Send a message.
  /// @param message, the message to send.
  /// @throw TransportException, if an error occurs during sending.
  virtual void send(MessageT const& msg) = 0;
};

/// @brief Message receiver
/// @details This class is responsible for receiving messages of type MessageT.
/// @tparam MessageT, the type of message to receive.
/// @tparam F, the type of callback function to call when a message is
/// received. Defaults to std::function<void(MessageT const&)>
template <typename MessageT>
class Receiver {
 public:
  using message_t = MessageT;
  using callback_t = std::function<void(message_t const&)>;

  /// @brief Default constructor deleted.
  Receiver() = delete;

  /// @brief Constructor.
  /// @param message_cb, the callback function to call when a message is
  ///                    received. The function must not modify shared state
  ///                    without protecting concurrent accesses and must not
  ///                    throw exceptions.
  /// @param worker, the worker to use for processing messages.
  /// @throws TransportException, if the message callback or worker is null.
  explicit Receiver(callback_t message_cb, std::shared_ptr<Worker> worker)
      : message_cb_(std::move(message_cb)), worker_(std::move(worker)) {
    if (!message_cb_) {
      throw TransportException("Message callback cannot be null.");
    }
    if (!worker_) {
      throw TransportException("Worker cannot be null.");
    }
  }

  /// @brief Destructor for the Receiver class.
  virtual ~Receiver() = default;

 protected:
  /// @brief Handle a received message.
  /// @details This function is called when a message is received.
  ///          It pushes the message to the worker for processing.
  ///          This method should not throw exceptions.
  /// @param message, the received message.
  void on_read(MessageT const& message) {
    worker_->push([this](message_t const& msg) { return message_cb_(msg); },
                  message);
  }

 private:
  callback_t message_cb_;
  std::shared_ptr<Worker> worker_;
};

/// @brief Client interface
/// @details This class defines the interface for a client that can send
/// requests
///          and receive responses synchronously or asynchronously.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class Client {
 public:
  /// @brief Default constructor deleted.
  Client() = delete;

  /// @brief Constructor that takes a shared pointer to a Worker.
  /// @details This constructor initializes the client with a worker that will
  /// be used to process requests and/or responses. The specifics are deferred
  /// to the derived classes.
  /// @param worker, the shared pointer to the Worker
  explicit Client(std::shared_ptr<Worker> worker)
      : worker_(std::move(worker)) {}

  /// @brief Default destructor.
  ~Client() = default;

  /// @brief Send a request synchronously.
  /// @param req, the request to send.
  /// @returns std::future<typename ServiceT::ResponseT>, a future that will
  /// hold the response.
  virtual typename ServiceT::ResponseT send_request(
      typename ServiceT::RequestT const& req) = 0;

  /// @brief Send a request asynchronously.
  /// @param req, the request to send.
  /// @returns std::future<typename ServiceT::ResponseT>, a future that will
  /// hold the response.
  virtual std::future<typename ServiceT::ResponseT> send_request_async(
      typename ServiceT::RequestT const& req) = 0;

 private:
  std::shared_ptr<Worker> worker_;
};

/// @brief Server interface
/// @details This class defines the interface for a server that can handle
/// requests
///          and send responses back to clients. Request handlers are functions
///          that
///       take a request of type ServiceT::RequestT and return a response of
///       type
///          ServiceT::ResponseT. The server uses a Worker to process requests
///          and/or
///       send responses. Whether the server handles requests synchronously or
///          asynchronously is deferred to the derived classes.
/// @tparam ServiceT, the service type
template <typename ServiceT>
class Server {
 public:
  using request_callback_t = std::function<typename ServiceT::ResponseT(
      typename ServiceT::RequestT const&)>;

  /// @brief Default constructor deleted.
  Server() = delete;

  /// @brief Constructor that takes a request callback and a shared pointer to a
  /// Worker.
  /// @details This constructor initializes the server with a request callback
  /// that will be called when a request is received, and a worker that will be
  /// used to process requests and/or send responses.
  /// @param request_cb, the callback function to call when a request is
  /// received.
  /// @param worker, the shared pointer to the Worker that will be used to
  ///                process requests and/or send responses.
  explicit Server(request_callback_t request_cb, std::shared_ptr<Worker> worker)
      : request_cb_(std::move(request_cb)), worker_(std::move(worker)) {}

  /// @brief Default destructor.
  ~Server() = default;

 protected:
  request_callback_t request_cb_;
  std::shared_ptr<Worker> worker_;
};

}  // namespace simpleio
