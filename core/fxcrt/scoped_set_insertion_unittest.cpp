// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/scoped_set_insertion.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(fxcrt, ScopedSetInsertion) {
  std::set<int> container;
  {
    ScopedSetInsertion<int> insertion(&container, 5);
    EXPECT_THAT(container, testing::UnorderedElementsAreArray({5}));

    std::unique_ptr<ScopedSetInsertion<int>> insertion2;
    {
      ScopedSetInsertion<int> insertion3(&container, 6);
      EXPECT_THAT(container, testing::UnorderedElementsAreArray({5, 6}));

      insertion2 = std::make_unique<ScopedSetInsertion<int>>(&container, 7);
      EXPECT_THAT(container, testing::UnorderedElementsAreArray({5, 6, 7}));
    }

    EXPECT_THAT(container, testing::UnorderedElementsAreArray({5, 7}));
    insertion2.reset();
    EXPECT_THAT(container, testing::UnorderedElementsAreArray({5}));
  }
  EXPECT_TRUE(container.empty());
}
