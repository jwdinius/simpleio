#pragma once
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include <gsl/span>

namespace simpleio {

template <typename T>
class SerializationStrategy {
public:
    ~SerializationStrategy() = default;
    
    virtual std::vector<std::byte> serialize(T const& entity) = 0;
    virtual T deserialize(std::vector<std::byte> const& blob) = 0;
};

template<typename T, size_t MaxBlobSize = 1024>
class Message {
public:

    using entity_type = T;
    static constexpr size_t max_blob_size = MaxBlobSize;

    Message() = delete;
    
    explicit Message(T const& entity, std::shared_ptr<SerializationStrategy<T>> strategy)
    : entity_(entity)
    , strategy_(strategy)
    {
        auto blob = strategy_->serialize(entity_);
        length_ = blob.size();
        std::copy(blob.begin(), blob.end(), blob_.begin());
    }

    explicit Message(T&& entity, std::shared_ptr<SerializationStrategy<T>> strategy)
    : entity_(std::move(entity))
    , strategy_(strategy)
    {
        auto blob = strategy_->serialize(entity_);
        length_ = blob.size();
        std::move(blob.begin(), blob.end(), blob_.begin());
    }
    
    explicit Message(std::vector<std::byte> const& blob, std::shared_ptr<SerializationStrategy<T>> strategy)
    : strategy_(strategy)
    {
        length_ = blob.size();
        std::copy(blob.begin(), blob.end(), blob_.begin());
        std::vector<std::byte> blob_copy {blob_.begin(), blob_.begin() + length_};
        entity_ = strategy_->deserialize(blob_copy);
    }

    explicit Message(std::vector<std::byte>&& blob, std::shared_ptr<SerializationStrategy<T>> strategy)
    : strategy_(strategy)
    {
        length_ = blob.size();
        std::move(blob.begin(), blob.end(), blob_.begin());
        std::vector<std::byte> blob_copy {blob_.begin(), blob_.begin() + length_};
        entity_ = strategy_->deserialize(blob_copy);
    }

    virtual ~Message() = default;

    T entity() const { return entity_; }
    
    gsl::span<const std::byte> blob() const { return gsl::span<const std::byte>(blob_.data(), length_); }

private:

    std::shared_ptr<SerializationStrategy<T>> strategy_;
    T entity_;
    std::vector<std::byte> blob_ {max_blob_size};
    size_t length_;
};
} // namespace simpleio