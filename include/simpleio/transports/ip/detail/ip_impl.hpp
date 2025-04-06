// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/asio.hpp>

/// @brief Namespace with implementation details for the
/// simpleio::transports::ip
///        module. Definitions within this namespace are not meant for public
///        use.
namespace simpleio::transports::ip::detail {
/// @brief Task scheduler implementation.
using TaskSchedulerImpl = boost::asio::io_context;
/// @brief LifecycleManager implementation.
// NOLINTBEGIN [whitespace/indent_namespace]
using LifecycleManagerImpl =
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
// NOLINTEND [whitespace/indent_namespace]
}  // namespace simpleio::transports::ip::detail
