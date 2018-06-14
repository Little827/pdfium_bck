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

  EXPECT_FALSE(GraphicsData({fNan, fNan, 1}) < GraphicsData({fNan, fNan, 1}));
  EXPECT_FALSE(GraphicsData({fInf, fNan, 1}) < GraphicsData({fInf, fNan, 1}));
  EXPECT_FALSE(GraphicsData({fMax, fNan, 1}) < GraphicsData({fMax, fNan, 1}));
  EXPECT_FALSE(GraphicsData({fMin, fNan, 1}) < GraphicsData({fMin, fNan, 1}));

  EXPECT_FALSE(GraphicsData({fNan, fNan, 1}) < GraphicsData({fInf, fNan, 1}));
  EXPECT_FALSE(GraphicsData({fInf, fNan, 1}) < GraphicsData({fMax, fNan, 1}));
  EXPECT_FALSE(GraphicsData({fMax, fNan, 1}) < GraphicsData({fMin, fNan, 1}));

  EXPECT_TRUE(GraphicsData({fInf, fNan, 1}) < GraphicsData({fNan, fNan, 1}));
  EXPECT_TRUE(GraphicsData({fMax, fNan, 1}) < GraphicsData({fInf, fNan, 1}));
  EXPECT_TRUE(GraphicsData({fMin, fNan, 1}) < GraphicsData({fMax, fNan, 1}));

  // Insert in reverse index permuted order.
  size_t x = 0;
  for (int c3 : {2, 1}) {
    for (float c1 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
      for (float c2 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
        graphics_map[{c1, c2, c3}] = x++;
      }
    }
  }
  EXPECT_EQ(72u, x);
  EXPECT_EQ(72u, graphics_map.size());

  x = 0;
  const int expected[72] = {
      71, 35, 70, 34, 69, 33, 68, 32, 67, 31, 66, 30, 65, 29, 64, 28, 63, 27,
      62, 26, 61, 25, 60, 24, 59, 23, 58, 22, 57, 21, 56, 20, 55, 19, 54, 18,
      53, 17, 52, 16, 51, 15, 50, 14, 49, 13, 48, 12, 47, 11, 46, 10, 45, 9,
      44, 8,  43, 7,  42, 6,  41, 5,  40, 4,  39, 3,  38, 2,  37, 1,  36, 0};
  for (const auto& item : graphics_map) {
    EXPECT_EQ(expected[x], item.second) << " for position " << x;
    ++x;
  }
  EXPECT_EQ(72u, x);

  // Erase in reverse index permuted order.
  for (int c3 : {1, 2}) {
    for (float c2 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
      for (float c1 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
        graphics_map.erase({c1, c2, c3});
      }
    }
  }
  EXPECT_EQ(0u, graphics_map.size());
}
