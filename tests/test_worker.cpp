// Copyright (c) 2025, Joe Dinius, Ph.D.
// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

#include "simpleio/worker.hpp"

namespace sio = simpleio;

// Example test case using the test harness
TEST(WorkerTest, Nominal) {
  // Create a default worker with a single thread
  auto worker = std::make_unique<sio::Worker>();

  // Check void return type task with no arguments
  auto void_fut = worker->push([]() -> void { return; });
  EXPECT_TRUE(void_fut.valid());
  EXPECT_NO_THROW(void_fut.get());  // Should not throw

  // Check int return type task with multiple arguments
  auto int_fut = worker->push(
      [](int a, int b, int c) -> int { return a * b * c; }, 2, 3, 4);
  EXPECT_TRUE(int_fut.valid());
  EXPECT_EQ(int_fut.get(), 24);  // 2 * 3 * 4 = 24
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
