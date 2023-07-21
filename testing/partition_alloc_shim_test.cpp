// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/partition_allocator/partition_address_space.h"
#include "testing/gtest/include/gtest/gtest.h"

class PartitionAllocShimTest : public ::testing::Test {};

TEST_F(PartitionAllocShimTest, Basic) {
  int* p = new int(42);

  // Memory allocated by operator new belongs to PartitionAlloc.
  ASSERT_TRUE(partition_alloc::IsManagedByPartitionAlloc(
      reinterpret_cast<uintptr_t>(p)));

  // Memory on stack obviously does not belong to PartitionAlloc.
  ASSERT_FALSE(partition_alloc::IsManagedByPartitionAlloc(
      reinterpret_cast<uintptr_t>(&p)));
}
