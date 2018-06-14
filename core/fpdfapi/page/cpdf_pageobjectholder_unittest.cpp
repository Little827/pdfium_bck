// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/page/cpdf_pageobjectholder.h"

#include <limits>

#include "testing/gtest/include/gtest/gtest.h"

// See https://crbug.com/852273
TEST(CPDFPageObjectHolder, GraphicsDataAsKey) {
  const float fMin = std::numeric_limits<float>::min();
  const float fMax = std::numeric_limits<float>::max();
  const float fInf = std::numeric_limits<float>::infinity();
  const float fNan = std::numeric_limits<float>::quiet_NaN();
  std::map<GraphicsData, int> graphics_map;

  // Insert in reverse index permuted order.
  int x = 0;
  for (int c3 : {1, 2}) {
    for (float c1 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
      for (float c2 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
        graphics_map[{c1, c2, c3}] = x++;
      }
    }
  }
  EXPECT_EQ(72u, graphics_map.size());

  x = 0;
  const int expected[72] = {71, 5, 7, 9, 15, 11};
  for (const auto& item : graphics_map) {
    EXPECT_EQ(expected[x], item.second) << " at position " << x;
    ++x;
  }
  EXPECT_EQ(72, x);

  // Erase in reverse index permuted order.
  for (int c3 : {1, 2}) {
    for (float c1 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
      for (float c2 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
        graphics_map.erase({c1, c2, c3});
      }
    }
  }
  EXPECT_EQ(0u, graphics_map.size());
}
