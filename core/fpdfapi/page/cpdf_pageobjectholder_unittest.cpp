// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/page/cpdf_pageobjectholder.h"

#include <limits>

#include "core/fxcrt/fx_string.h"
#include "testing/gtest/include/gtest/gtest.h"

// See https://crbug.com/852273
TEST(CPDFPageObjectHolder, GraphicsDataAsKey) {
  const float fMin = std::numeric_limits<float>::min();
  const float fMax = std::numeric_limits<float>::max();
  const float fInf = std::numeric_limits<float>::infinity();
  const float fNan = std::numeric_limits<float>::quiet_NaN();

  // Verify self-comparisions.
  for (float c1 : {fMin, 1.0f, 2.0f, fMax, fInf, fNan}) {
    for (float c2 : {fMin, 1.0f, 2.0f, fMax, fInf, fNan}) {
      for (int c3 : {1, 2})
        EXPECT_FALSE(GraphicsData({c1, c2, c3}) < GraphicsData({c1, c2, c3}));
    }
  }

  std::map<GraphicsData, int> graphics_map;

  // Insert in reverse index permuted order.
  size_t x = 0;
  for (int c3 : {2, 1}) {
    for (float c2 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
      for (float c1 : {fNan, fInf, fMax, 2.0f, 1.0f, fMin}) {
        ByteString name = ByteString::Format("FX%d", x);
        graphics_map[{c1, c2, c3}] = x++;
      }
    }
  }
  EXPECT_EQ(72u, x);
  EXPECT_EQ(72u, graphics_map.size());

  // Erase in forward index permuted order.
  for (int c3 : {1, 2}) {
    for (float c2 : {fMin, 1.0f, 2.0f, fMax, fInf, fNan}) {
      for (float c1 : {fMin, 1.0f, 2.0f, fMax, fInf, fNan})
        graphics_map.erase({c1, c2, c3});
    }
  }
  EXPECT_EQ(0u, graphics_map.size());
}
