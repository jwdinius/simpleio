#pragma once
#include <async_queue.hpp>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>

namespace simpleio {
enum class TaskStatus { Running, Succeeded, Failed };

/// @brief Exception thrown when a task execution error occurs.
class TaskExecutionError : public std::runtime_error {
 public:
  explicit TaskExecutionError(std::string const& what)
      : std::runtime_error(what) {}
};

class TaskHandleBase {
 public:
  virtual ~TaskHandle() = default;
  virtual TaskStatus status() const = 0;
  virtual std::unique_ptr<void> get_result_erased_type() = 0;
};

template <typename T>
class TaskHandle : public TaskHandleBase {
 public:
  using result_type = T;

  virtual ~TaskHandle() = default;
  virtual TaskStatus status() const = 0;
  std::optional<T> get_result() {
    auto* result = get_result_erased_type();
    if (result) {
      return *reinterpret_cast<T*>(result.get());
    }
    return std::nullopt;
  }
};

class TaskExecutor {
 public:
  virtual ~TaskExecutor() = default;

  template <typename FnT>
  using TaskHandlePtr = std::shared_ptr<TaskHandle<std::invoke_result_t<FnT>>>;

  // TODO: figure out how to abstract task_execution
  template <typename FnT>
  TaskHandlePtr<FnT> execute(FnT&& task_fn) {
    auto task =
        std::make_shared<std::function<void()>>(std::forward<FnT>(task_fn));
    auto task_handle =
        std::make_unique<TaskHandle<std::invoke_result_t<FnT>>>();
    task_handle->set_status(TaskStatus::Running);
    task_queue_.push([this, task, task_handle]() mutable {
      try {
        execute_task(*task);
        task_handle->set_status(TaskStatus::Succeeded);
      } catch (const std::exception& e) {
        task_handle->set_status(TaskStatus::Failed);
        throw TaskExecutionError(e.what());
      }
    });
  }

 protected:
  virtual void execute_task(std::function<void()> task) = 0;
  AsyncQueue<std::function<void()>> task_queue_;
};

}  // namespace simpleio
