// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace simpleio {

/// @brief Default maximum size of a serialized data structure.
static constexpr size_t DEFAULT_MAX_BLOB_SIZE = 1024;

/// @brief Exception thrown when a serialization or deserialization error
/// occurs.
class SerializerError : public std::runtime_error {
 public:
  explicit SerializerError(std::string const& what)
      : std::runtime_error(what) {}
};

/// @brief Strategy for serializing and deserializing data structures with
/// templated type.
/// @details Implementations of this class are responsible for converting data
/// structures of type T
///          into strings and vice versa. They are also responsible for
///          throwing SerializerError exceptions when serialization or
///          deserialization fails.
/// @tparam T, the type of the data structure to serialize and deserialize.
/// @tparam MaxBlobSize, the maximum size of the serialized data structure,
/// defaulting to 1024 bytes.
template <typename T, size_t MaxBlobSize = DEFAULT_MAX_BLOB_SIZE>
class Serializer {
 public:
  using entity_t = T;
  static constexpr size_t max_blob_size = MaxBlobSize;

  /// @brief Declare default destructor to allow inheritance.
  ~Serializer() = default;

  /// @brief Serialize a data structure of type T into a string.
  /// @param entity, the data structure to serialize.
  /// @return std::string, the serialized data structure.
  /// @throw SerializerError, if an error occurs during serialization.
  virtual std::string serialize(entity_t const& entity) = 0;

  /// @brief Deserialize a string into a data structure of type T.
  /// @param blob, the string to deserialize.
  /// @return T, the deserialized data structure.
  /// @throw SerializerError, if an error occurs during deserialization.
  virtual entity_t deserialize(std::string const& blob) = 0;
};

/// @brief A message class encapsulating a data structure of type T and its
/// serialization strategy.
/// @details Constructors of this class rely on dependency injection of a
/// serializer to serialize and deserialize the data structure.
/// @tparam SerializerT, the type of the serialization strategy to use.
template <typename SerializerT>
class Message {
 public:
  using entity_t = typename SerializerT::entity_t;
  using serializer_t = SerializerT;
  static constexpr size_t max_blob_size = SerializerT::max_blob_size;

  /// @brief Default constructor deleted.
  Message() = delete;

  /// @brief Default destructor.
  ~Message() = default;

  /// @brief Construct from a SerializerT object and a data structure of type
  /// entity_t.
  /// @param entity, the data structure to encapsulate.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializerError, if an error occurs during serialization.
  explicit Message(entity_t const& entity,
                   std::shared_ptr<serializer_t> strategy)
      : entity_(entity),
        strategy_(std::move(strategy)),
        blob_(serializer_t::max_blob_size, '\0') {
    blob_init();
  }

  /// @brief Construct from a entity_t object.
  /// @param entity, the data structure to encapsulate.
  /// @throw SerializerError, if an error occurs during serialization.
  explicit Message(entity_t const& entity)
      : entity_(entity),
        strategy_(std::make_shared<serializer_t>()),
        blob_(serializer_t::max_blob_size, '\0') {
    blob_init();
  }

  /// @brief Construct from a SerializerT object and a moved data structure of
  /// type entity_t.
  /// @param entity, the data structure to encapsulate.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializerError, if an error occurs during serialization.
  explicit Message(entity_t&& entity, std::shared_ptr<serializer_t> strategy)
      : entity_(std::move(entity)),
        strategy_(std::move(strategy)),
        blob_(serializer_t::max_blob_size, '\0') {
    auto _blob = strategy_->serialize(entity_);
    if (_blob.size() > serializer_t::max_blob_size) {
      throw SerializerError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::move(_blob.begin(), _blob.end(), blob_.begin());
  }

  /// @brief Construct from a moved data structure of type
  /// entity_t.
  /// @param entity, the data structure to encapsulate.
  /// @throw SerializerError, if an error occurs during serialization.
  explicit Message(entity_t&& entity)
      : entity_(std::move(entity)),
        strategy_(std::make_shared<serializer_t>()),
        blob_(serializer_t::max_blob_size, '\0') {
    blob_init();
  }

  /// @brief Construct from a SerializerT object and a serialized string.
  /// @param blob, the serialized string.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializerError, if an error occurs during serialization.
  /// @details This constructor is only compiled if entity_t is not
  /// a string.
  template <typename U = SerializerT,
            typename = std::enable_if_t<
                !std::is_same_v<typename U::entity_t, std::string>>>
  explicit Message(
      std::string const& _blob,  // NOLINT [modernize-pass-by-value]
      std::shared_ptr<serializer_t> strategy)
      : strategy_(std::move(strategy)), blob_(_blob) {
    entity_init();
  }

  /// @brief Construct from a SerializerT object and a moved serialized string.
  /// @param blob, the serialized string.
  /// @param strategy, the serialization strategy to use.
  /// @throw SerializerError, if an error occurs during serialization.
  /// @details This constructor is only compiled if SerializerT::entity_t is not
  /// a string.
  template <typename U = SerializerT,
            typename = std::enable_if_t<
                !std::is_same_v<typename U::entity_t, std::string>>>
  explicit Message(std::string&& _blob, std::shared_ptr<serializer_t> strategy)
      : strategy_(std::move(strategy)), blob_(std::move(_blob)) {
    entity_init();
  }

  /// @brief Construct from a serialized string.
  /// @param blob, the serialized string.
  /// @throw SerializerError, if an error occurs during serialization.
  /// @details This constructor is only compiled if SerializerT::entity_t is not
  /// a string.
  template <typename U = SerializerT,
            typename = std::enable_if_t<
                !std::is_same_v<typename U::entity_t, std::string>>>
  explicit Message(
      std::string const& _blob)  // NOLINT [modernize-pass-by-value]
      : strategy_(std::make_shared<serializer_t>()), blob_(_blob) {
    entity_init();
  }

  /// @brief Construct from a moved serialized string.
  /// @param blob, the serialized string.
  /// @throw SerializerError, if an error occurs during serialization.
  /// @details This constructor is only compiled if SerializerT::entity_t is not
  /// a string.
  template <typename U = SerializerT,
            typename = std::enable_if_t<
                !std::is_same_v<typename U::entity_t, std::string>>>
  explicit Message(std::string&& _blob)
      : strategy_(std::make_shared<serializer_t>()), blob_(std::move(_blob)) {
    entity_init();
  }

  /// @brief Return the data structure in native format.
  /// @return T, the native data type of the Message.
  [[nodiscard]] entity_t entity() const {
    return entity_;
  }

  /// @brief Return the serialized data structure.
  /// @return the serialized data
  /// structure.
  [[nodiscard]] std::string blob() const {
    return blob_;
  }

  /// @brief Return the serialization strategy used by the Message.
  /// @return std::shared_ptr<SerializerT>, the serialization strategy.
  [[nodiscard]] std::shared_ptr<serializer_t> serializer() const {
    return strategy_;
  }

 private:
  /// @brief Common initialization for blob serialization from entity.
  /// @throws SerializerError, if the serialized blob exceeds the maximum size.
  void blob_init() {
    auto _blob = strategy_->serialize(entity_);
    if (_blob.size() > SerializerT::max_blob_size) {
      throw SerializerError("Blob size exceeds maximum size.");
    }
    blob_.resize(_blob.size());
    std::copy(_blob.begin(), _blob.end(), blob_.begin());
  }

  /// @brief Common initialization for entity deserialization from blob.
  /// @throws SerializerError, if the serialized blob exceeds the maximum size.
  void entity_init() {
    if (blob_.size() > SerializerT::max_blob_size) {
      throw SerializerError("Blob size exceeds maximum size.");
    }
    entity_ = strategy_->deserialize(blob_);
  }

  std::shared_ptr<serializer_t> strategy_;
  entity_t entity_;
  std::string blob_;
};

// NOLINTBEGIN [build/namespaces]
template <typename RequestSerializer,
          typename ResponseSerializer = RequestSerializer>
// NOLINTEND [build/namespaces]
class Service {
 public:
  using RequestT = Message<RequestSerializer>;
  using ResponseT = Message<ResponseSerializer>;
};
}  // namespace simpleio
