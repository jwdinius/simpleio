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
template <typename Body>
class HttpRequestType : public boost::beast::http::request<Body> {
 public:
  using body_t = Body;

  /// @brief Default constructor.
  HttpRequestType() = default;
};

/// @brief Serialize and deserialize HTTP requests.
/// @details HTTP requests are serialized and deserialized using Boost Beast
/// library.
/// @tparam RequestT, the HTTP request type.
template <typename RequestT, size_t MaxBlobSize = DEFAULT_MAX_BLOB_SIZE>
class HttpRequestSerializer : public Serializer<RequestT, MaxBlobSize> {
 public:
  /// @brief Serialize an RequestT object into a string.
  /// @param entity, the RequestT object to serialize.
  /// @return std::string, the serialized RequestT object.
  /// @throw SerializerError, if an error occurs during serialization.
  std::string serialize(RequestT const& entity) override {
    try {
      std::ostringstream oss;
      oss << entity;
      return oss.str();
    } catch (std::exception const& e) {
      throw SerializerError(e.what());
    }
  }

  /// @brief Deserialize a string into an RequestT object.
  /// @param blob, the string to deserialize.
  /// @return RequestT, the deserialized object.
  /// @throw SerializerError, if an error occurs during deserialization.
  RequestT deserialize(std::string const& blob) override {
    try {
      boost::beast::error_code err_code;
      boost::beast::http::request_parser<typename RequestT::body_t> parser;
      parser.body_limit(std::numeric_limits<std::uint64_t>::max());
      parser.eager(true);  // Needed for parsing the body
      parser.put(boost::asio::buffer(blob), err_code);
      if (err_code) {
        throw SerializerError("Failed to parse HTTP request: " +
                              err_code.message());
      }
      parser.put_eof(err_code);
      if (err_code) {
        throw SerializerError("Failed to finalize HTTP request: " +
                              err_code.message());
      }
      HttpRequestType<typename RequestT::body_t> req;
      static_cast<boost::beast::http::request<typename RequestT::body_t>&>(
          req) = parser.release();
      return req;
    } catch (std::exception const& e) {
      throw SerializerError(e.what());
    }
  }
};

/// @brief Define HttpResponseType as a Boost Beast HTTP response.
/// @tparam Body, the body type of the HTTP response, default is
///         boost::beast::http::string_body.
template <typename Body>
class HttpResponseType : public boost::beast::http::response<Body> {
 public:
  using body_t = Body;

  /// @brief Default constructor.
  HttpResponseType() = default;
};

/// @brief Serialize and deserialize HTTP responses.
/// @details HTTP responses are serialized and deserialized using Boost Beast
/// library.
/// @tparam Body, the body type of the HTTP response, default is
///         boost::beast::http::string_body.
template <typename ResponseT, size_t MaxBlobSize = DEFAULT_MAX_BLOB_SIZE>
class HttpResponseSerializer : public Serializer<ResponseT, MaxBlobSize> {
 public:
  /// @brief Serialize a ResponseT object into a string.
  /// @param entity, the ResponseT object to serialize.
  /// @return std::string, the serialized ResponseT object.
  /// @throw SerializerError, if an error occurs during serialization.
  std::string serialize(ResponseT const& entity) override {
    try {
      std::ostringstream oss;
      oss << entity;
      return oss.str();
    } catch (std::exception const& e) {
      throw SerializerError(e.what());
    }
  }

  /// @brief Deserialize a string into an ResponseT object.
  /// @param blob, the string to deserialize.
  /// @return ResponseT, the deserialized ResponseT object.
  /// @throw SerializerError, if an error occurs during deserialization.
  ResponseT deserialize(std::string const& blob) override {
    try {
      boost::beast::error_code err_code;
      boost::beast::http::response_parser<typename ResponseT::body_t> parser;
      parser.body_limit(std::numeric_limits<std::uint64_t>::max());
      parser.eager(true);  // Needed for parsing the body
      parser.put(boost::asio::buffer(blob), err_code);
      if (err_code) {
        throw SerializerError("Failed to parse HTTP response: " +
                              err_code.message());
      }
      parser.put_eof(err_code);
      if (err_code) {
        throw SerializerError("Failed to finalize HTTP response: " +
                              err_code.message());
      }
      HttpResponseType<typename ResponseT::body_t> resp;
      static_cast<boost::beast::http::response<typename ResponseT::body_t>&>(
          resp) = parser.release();
      return resp;
    } catch (std::exception const& e) {
      throw SerializerError(e.what());
    }
  }
};

}  // namespace simpleio::messages
