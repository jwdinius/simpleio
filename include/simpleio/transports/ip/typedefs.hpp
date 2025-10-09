// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include "simpleio/message.hpp"

namespace simpleio::transports::ip {

static constexpr size_t UDP_BLOB_SIZE{1400};
static constexpr size_t TCP_BLOB_SIZE{64000};

template <typename EntityT>
using TcpSerializer = Serializer<EntityT, TCP_BLOB_SIZE>;

template <typename EntityT>
using UdpSerializer = Serializer<EntityT, UDP_BLOB_SIZE>;

template <typename EntityT>
using TcpMessage = Message<TcpSerializer<EntityT>>;

template <typename EntityT>
using UdpMessage = Message<UdpSerializer<EntityT>>;

/// @brief Credentials files for TLS v1.3 transport.
/// @details This struct holds the paths to the Certificate Authority (CA) file,
///          the certificate file, and the private key file.
struct TlsCredentials {
  std::filesystem::path ca_file;
  std::filesystem::path cert_file;
  std::filesystem::path key_file;
};

struct Endpoint {
  std::string ip{"127.0.0.1"};
  uint16_t port{5555};
};

struct TcpOptions {
  Endpoint endpoint;
  bool streaming{false};
  std::shared_ptr<simpleio::Framer> framer{
      std::make_shared<simpleio::DefaultFramer>()};
};

struct TlsOptions {
  TcpOptions tcp_options;
  TlsCredentials credentials;
};

struct UdpOptions {
  Endpoint endpoint;
  bool broadcast{false};
  std::optional<uint8_t> ttl;
  std::optional<bool> loopback;
  std::optional<uint8_t> interface_v6;
};

using Options = std::variant<TcpOptions, TlsOptions, UdpOptions>;

struct HttpOptions {
  Endpoint endpoint;
  std::chrono::duration<int> timeout{5};
};

struct HttpsOptions {
  HttpOptions http_options;
  TlsCredentials credentials;
};

using ServiceOptions = std::variant<HttpOptions, HttpsOptions>;
}  // namespace simpleio::transports::ip
