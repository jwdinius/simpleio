// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0#pragma once
#pragma once
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace simpleio {

static constexpr size_t DEFAULT_MAX_BLOB_SIZE = 1024;

/// @brief Exception thrown when a serialization or deserialization error
/// occurs.
class SerializationError : public std::runtime_error {
 public:
  explicit SerializationError(std::string const& what)
      : std::runtime_error(what) {}
};

/// @brief Strategy for serializing and deserializing data structures with
/// templated type.
/// @details Implementations of this class are responsible for converting data
/// structures of type T
///          into strings and vice versa. They are also responsible for
///          throwing SerializationError exceptions when serialization or
///          deserialization fails.
/// @tparam T, the type of the data structure to serialize and deserialize.
template <typename T>
class SerializationStrategy {
 public:
  /// @brief Declare default destructor to allow inheritance.
  ~SerializationStrategy() = default;

  /// @brief Serialize a data structure of type T into a string.
  /// @param entity, the data structure to serialize.
  /// @return std::string, the serialized data structure.
  /// @throw SerializationError, if an error occurs during serialization.
  virtual std::string serialize(T const& entity) = 0;

  /// @brief Deserialize a string into a data structure of type T.
  /// @param blob, the string to deserialize.
  /// @return T, the deserialized data structure.
  /// @throw SerializationError, if an error occurs during deserialization.
  virtual T deserialize(std::string const& blob) = 0;
};

/// @brief A message class encapsulating a data structure of type T and its
/// serialized form.
/// @details Constructors of this class rely on dependency injection of a
/// SerializationStrategy<T> object
///          to serialize and deserialize the data structure.
/// @tparam T, the type of the data structure to encapsulate.
/// @tparam MaxBlobSize, the maximum size of the serialized data structure (in
/// bytes). (default: 1024)
template <typename T, size_t MaxBlobSize = DEFAULT_MAX_BLOB_SIZE>
class Message {
 public:
  /// @brief Expose the type definition of the data structure encapsulated by
  /// this message.
  using entity_type = T;

  /// @brief Expose the maximum size of the serialized data structure.
  static constexpr size_t max_blob_size = MaxBlobSize;

  /// @brief Default constructor deleted.
  Message() = delete;

  /// @brief Construct from a data structure of type T and a
  /// SerializationStrategy<T> object.
  /// @param entity, the data structure to encapsulate.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializationError, if an error occurs during serialization.
  explicit Message(T const& entity,
                   std::shared_ptr<SerializationStrategy<T>> strategy)
      : entity_(entity),
        strategy_(std::move(strategy)),
        blob_(max_blob_size, '\0') {
    auto _blob = strategy_->serialize(entity_);
    if (_blob.size() > max_blob_size) {
      throw SerializationError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::copy(_blob.begin(), _blob.end(), blob_.begin());
  }

  /// @brief Construct from a moved data structure of type T and a
  /// SerializationStrategy<T> object.
  /// @param entity, the data structure to encapsulate.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializationError, if an error occurs during serialization.
  explicit Message(T&& entity,
                   std::shared_ptr<SerializationStrategy<T>> strategy)
      : entity_(std::move(entity)),
        strategy_(std::move(strategy)),
        blob_(max_blob_size, '\0') {
    auto _blob = strategy_->serialize(entity_);
    if (_blob.size() > max_blob_size) {
      throw SerializationError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::move(_blob.begin(), _blob.end(), blob_.begin());
  }

  /// @brief Construct a message from a string and a
  /// SerializationStrategy<T> object.
  /// @param blob, the string to deserialize and encapsulate
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializationError, if an error occurs during deserialization.
  /// @details This constructor is only compiled if T is not a string.
  template <typename U = T,
            typename = std::enable_if_t<!std::is_same_v<U, std::string>>>
  explicit Message(std::string const& _blob,
                   std::shared_ptr<SerializationStrategy<T>> strategy)
      : strategy_(std::move(strategy)), blob_(max_blob_size, '\0') {
    if (_blob.size() > max_blob_size) {
      throw SerializationError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::copy(_blob.begin(), _blob.end(), blob_.begin());
    entity_ = strategy_->deserialize(blob_);
  }

  /// @brief Construct from a string and a SerializationStrategy<T>
  /// object.
  /// @param blob, the string to deserialize and encapsulate
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializationError, if an error occurs during deserialization.
  /// @details This constructor is only compiled if T is not a string.
  template <typename U = T,
            typename = std::enable_if_t<!std::is_same_v<U, std::string>>>
  explicit Message(std::string&& _blob,
                   std::shared_ptr<SerializationStrategy<T>> strategy)
      : strategy_(std::move(strategy)), blob_(max_blob_size, '\0') {
    if (_blob.size() > max_blob_size) {
      throw SerializationError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::move(_blob.begin(), _blob.end(), blob_.begin());
    entity_ = strategy_->deserialize(blob_);
  }

  virtual ~Message() = default;

  /// @brief Return the data structure in native format.
  /// @return T, the native data type of the Message.
  [[nodiscard]] T entity() const {
    return entity_;
  }

  /// @brief Return the serialized data structure.
  /// @return the serialized data
  /// structure.
  [[nodiscard]] std::string blob() const {
    return blob_;
  }

 private:
  std::shared_ptr<SerializationStrategy<T>> strategy_;
  T entity_;
  std::string blob_;
};
}  // namespace simpleio
