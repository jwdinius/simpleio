#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

namespace simpleio {

/// @brief A thread-safe queue for storing messages of type T.
/// @details This class provides a thread-safe queue for storing messages of type T.
///          It is intended for use in asynchronous I/O operations where messages
///          are received and processed in separate threads.
/// @tparam T, the type of message to store in the queue.
template <typename T>
class AsyncQueue {
public:

    /// @brief Push a message onto the queue.
    /// @param value, the message to push onto the queue.
    void push(T value) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(value));
        cv_.notify_one();
    }
    
    /// @brief Attempt to pop a message from the queue.
    /// @param value, a reference to the value that will receive the popped message.
    /// @return bool, true if a message was successfully popped, false otherwise.
    bool try_pop(T& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        value = std::move(queue_.front());
        queue_.pop();
        return true;
    }
    
    /// @brief Wait for and pop a message from the queue.
    /// @return T, the popped message.
    T wait_and_pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty(); });
        T value = std::move(queue_.front());
        queue_.pop();
        return value;
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
};
}  // namespace simpleio