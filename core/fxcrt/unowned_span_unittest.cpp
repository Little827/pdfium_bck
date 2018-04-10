// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test pdfium extensions to span beyond base::span<>

#include "core/fxcrt/unowned_span.h"

#include <utility>
#include <vector>

#include "testing/gtest/include/gtest/gtest.h"

TEST(UnownedSpan, OperatorBool) {
  UnownedSpan<int> empty_span;
  EXPECT_FALSE(empty_span);

  int stuff[] = {1, 2, 3};
  UnownedSpan<int> stuff_span(stuff);
  EXPECT_TRUE(stuff_span);

  // Advancing to the end of a span makes it false.
  EXPECT_FALSE(stuff_span.last(0));
}

TEST(UnownedSpan, OperatorPlusPlus) {
  int stuff[] = {1, 2, 3};
  UnownedSpan<int> stuff_span(stuff);
  EXPECT_EQ(1, *stuff_span);
  EXPECT_EQ(2, *(++stuff_span));
  EXPECT_EQ(2, *stuff_span++);
  EXPECT_EQ(3, *stuff_span++);
  EXPECT_FALSE(stuff_span);
}

TEST(UnownedSpan, OperatorPlusEquals) {
  int stuff[] = {1, 2, 3};
  UnownedSpan<int> stuff_span(stuff);
  stuff_span += 2;
  EXPECT_EQ(3, *stuff_span);

  // Reset it.
  stuff_span = UnownedSpan<int>(stuff);
  stuff_span += 3;
  EXPECT_FALSE(stuff_span);
}

TEST(UnownedSpan, CheckedErrors) {
  UnownedSpan<int> empty_span;
  EXPECT_DEATH(empty_span[0], ".*");
  EXPECT_DEATH(*empty_span, ".*");
  EXPECT_DEATH(empty_span++, ".*");
  EXPECT_DEATH(++empty_span, ".*");
  EXPECT_DEATH(empty_span += 1, ".*");

  int stuff[] = {1, 2, 3};
  UnownedSpan<int> stuff_span(stuff);
  EXPECT_DEATH(stuff_span += 4, ".*");

  stuff_span = stuff_span.last(0);
  EXPECT_DEATH(stuff_span[0], ".*");
  EXPECT_DEATH(*stuff_span, ".*");
  EXPECT_DEATH(stuff_span++, ".*");
  EXPECT_DEATH(++stuff_span, ".*");
}
