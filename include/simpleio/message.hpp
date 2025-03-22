#pragma once
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include <gsl/span>

namespace simpleio {

/// @brief Exception thrown when a serialization or deserialization error occurs.
class SerializationError : public std::runtime_error {
public:
    explicit SerializationError(std::string const& what) : std::runtime_error(what) {}
};

/// @brief Strategy for serializing and deserializing data structures with templated type.
/// @details Implementations of this class are responsible for converting data structures of type T
///          into byte vectors and vice versa. They are also responsible for throwing SerializationError
///          exceptions when serialization or deserialization fails.
/// @tparam T, the type of the data structure to serialize and deserialize. 
template <typename T>
class SerializationStrategy {
public:
    
    /// @brief Declare default destructor to allow inheritance.
    ~SerializationStrategy() = default;
    
    /// @brief Serialize a data structure of type T into a byte vector.
    /// @param entity, the data structure to serialize. 
    /// @return std::vector<std::byte>, the serialized data structure.
    /// @throw SerializationError, if an error occurs during serialization.
    virtual std::vector<std::byte> serialize(T const& entity) = 0;

    /// @brief Deserialize a byte vector into a data structure of type T.
    /// @param blob, the byte vector to deserialize.
    /// @return T, the deserialized data structure.
    /// @throw SerializationError, if an error occurs during deserialization.
    virtual T deserialize(std::vector<std::byte> const& blob) = 0;
};

/// @brief A message class encapsulating a data structure of type T and its serialized form.
/// @details Constructors of this class rely on dependency injection of a SerializationStrategy<T> object
///          to serialize and deserialize the data structure.
/// @tparam T, the type of the data structure to encapsulate.
/// @tparam MaxBlobSize, the maximum size of the serialized data structure (in bytes). (default: 1024)
template<typename T, size_t MaxBlobSize = 1024>
class Message {
public:

    /// @brief Expose the type definition of the data structure encapsulated by this message.
    using entity_type = T;

    /// @brief Expose the maximum size of the serialized data structure.
    static constexpr size_t max_blob_size = MaxBlobSize;

    /// @brief Default constructor deleted.
    Message() = delete;
    
    /// @brief Construct from a data structure of type T and a SerializationStrategy<T> object.
    /// @param entity, the data structure to encapsulate.
    /// @param strategy, the serialization strategy to use.
    /// @throw SerializationError, if an error occurs during serialization.
    explicit Message(T const& entity, std::shared_ptr<SerializationStrategy<T>> strategy)
    : entity_(entity)
    , strategy_(strategy)
    {
        auto blob = strategy_->serialize(entity_);
        length_ = blob.size();
        std::copy(blob.begin(), blob.end(), blob_.begin());
    }

    /// @brief Construct from a moved data structure of type T and a SerializationStrategy<T> object.
    /// @param entity, the data structure to encapsulate.
    /// @param strategy, the serialization strategy to use.
    /// @throw SerializationError, if an error occurs during serialization.
    explicit Message(T&& entity, std::shared_ptr<SerializationStrategy<T>> strategy)
    : entity_(std::move(entity))
    , strategy_(strategy)
    {
        auto blob = strategy_->serialize(entity_);
        length_ = blob.size();
        std::move(blob.begin(), blob.end(), blob_.begin());
    }
    
    /// @brief Construct a message from a byte vector and a SerializationStrategy<T> object.
    /// @param blob, the byte vector to deserialize and encapsulate
    /// @param strategy, the serialization strategy to use.
    /// @throw SerializationError, if an error occurs during deserialization.
    explicit Message(std::vector<std::byte> const& blob, std::shared_ptr<SerializationStrategy<T>> strategy)
    : strategy_(strategy)
    {
        length_ = blob.size();
        std::copy(blob.begin(), blob.end(), blob_.begin());
        std::vector<std::byte> blob_copy {blob_.begin(), blob_.begin() + length_};
        entity_ = strategy_->deserialize(blob_copy);
    }

    /// @brief Construct from a moved byte vector and a SerializationStrategy<T> object.
    /// @param blob, the byte vector to deserialize and encapsulate
    /// @param strategy, the serialization strategy to use.
    /// @throw SerializationError, if an error occurs during deserialization.
    explicit Message(std::vector<std::byte>&& blob, std::shared_ptr<SerializationStrategy<T>> strategy)
    : strategy_(strategy)
    {
        length_ = blob.size();
        std::move(blob.begin(), blob.end(), blob_.begin());
        std::vector<std::byte> blob_copy {blob_.begin(), blob_.begin() + length_};
        entity_ = strategy_->deserialize(blob_copy);
    }

    virtual ~Message() = default;

    /// @brief Return the data structure in native format.
    /// @return T, the native data type of the Message.
    T entity() const { return entity_; }
    
    /// @brief Return (a view of) the serialized data structure.
    /// @return gsl::span<const std::byte>, a view of the serialized data structure.
    gsl::span<const std::byte> blob() const { return gsl::span<const std::byte>(blob_.data(), length_); }

private:

    std::shared_ptr<SerializationStrategy<T>> strategy_;
    T entity_;
    std::vector<std::byte> blob_ {max_blob_size};
    size_t length_;
};
} // namespace simpleio