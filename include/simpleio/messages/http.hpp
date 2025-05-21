// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/version.hpp>
#include <memory>
#include <sstream>
#include <string>

#include "simpleio/message.hpp"

namespace simpleio::messages {

/// @brief Define HttpRequestType as a Boost Beast HTTP request.
/// @tparam Body, the body type of the HTTP request.
template <typename Body = boost::beast::http::string_body>
using HttpRequestType = boost::beast::http::request<Body>;

/// @brief Serialize and deserialize HTTP requests.
/// @details HTTP requests are serialized and deserialized using Boost Beast
/// library.
/// @tparam Body, the body type of the HTTP request.
template <typename Body = boost::beast::http::string_body>
class HttpRequestSerializer
    : public SerializationStrategy<HttpRequestType<Body>> {
 public:
  using HttpRequestT = HttpRequestType<Body>;

  /// @brief Serialize an HttpRequestType object into a string.
  /// @param entity, the HttpRequestType object to serialize.
  /// @return std::string, the serialized HttpRequestType object.
  /// @throw SerializationError, if an error occurs during serialization.
  std::string serialize(HttpRequestT const& entity) override {
    try {
      std::ostringstream oss;
      oss << entity;
      return oss.str();
    } catch (std::exception const& e) {
      throw SerializationError(e.what());
    }
  }

  /// @brief Deserialize a string into an HttpRequestType object.
  /// @param blob, the string to deserialize.
  /// @return HttpRequestT, the deserialized HttpRequestType object.
  /// @throw SerializationError, if an error occurs during deserialization.
  HttpRequestT deserialize(std::string const& blob) override {
    try {
      boost::beast::error_code ec;
      boost::beast::http::request_parser<Body> parser;
      parser.body_limit(std::numeric_limits<std::uint64_t>::max());
      parser.eager(true);  // Needed for parsing the body
      parser.put(boost::asio::buffer(blob), ec);
      if (ec) {
        throw SerializationError("Failed to parse HTTP request: " +
                                 ec.message());
      }
      parser.put_eof(ec);
      if (ec) {
        throw SerializationError("Failed to finalize HTTP request: " +
                                 ec.message());
      }

      return parser.release();
    } catch (std::exception const& e) {
      throw SerializationError(e.what());
    }
  }
};

}  // namespace simpleio::messages
