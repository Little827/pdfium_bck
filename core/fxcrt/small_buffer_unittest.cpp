// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/small_buffer.h"

#include <algorithm>

#include "testing/gtest/include/gtest/gtest.h"

namespace fxcrt {

TEST(SmallBuffer, Empty) {
  SmallBuffer<int, 4> buffer(0);
  EXPECT_EQ(buffer.begin(), buffer.end());
}

TEST(SmallBuffer, NoFixed) {
  SmallBuffer<int, 0> buffer(4);
  std::fill(buffer.begin(), buffer.end(), 42);
  int* ptr = buffer.data();
  ASSERT_NE(nullptr, ptr);
  EXPECT_EQ(42, ptr[0]);
  EXPECT_EQ(42, ptr[1]);
  EXPECT_EQ(42, ptr[2]);
  EXPECT_EQ(42, ptr[3]);
}

TEST(SmallBuffer, NoFixedEmpty) {
  SmallBuffer<int, 0> buffer(0);
  EXPECT_EQ(buffer.begin(), buffer.end());
}

TEST(SmallBuffer, Fixed) {
  SmallBuffer<int, 4> buffer(2);
  std::fill(buffer.begin(), buffer.end(), 42);
  int* ptr = buffer.data();
  ASSERT_NE(nullptr, ptr);
  EXPECT_EQ(42, ptr[0]);
  EXPECT_EQ(42, ptr[1]);

  // Touching the unused fixed part is allowed and zero-initialized.
  EXPECT_EQ(0, ptr[2]);
  EXPECT_EQ(0, ptr[3]);
}

TEST(SmallBuffer, Dynamic) {
  SmallBuffer<int, 2> buffer(4);
  std::fill(buffer.begin(), buffer.end(), 42);
  int* ptr = buffer.data();
  ASSERT_NE(nullptr, ptr);
  EXPECT_EQ(42, ptr[0]);
  EXPECT_EQ(42, ptr[1]);
  EXPECT_EQ(42, ptr[2]);
  EXPECT_EQ(42, ptr[3]);
}

}  // namespace fxcrt
