// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_colorspace.h"

#include <stdint.h>

#include "core/fxcrt/retain_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(CPDF_CalRGB, TranslateImageLine) {
  const uint8_t kSrc[12] = {255, 0, 0, 0, 255, 0, 0, 0, 255, 128, 128, 128};
  const uint8_t kExpectMask[12] = {0, 0, 255, 204, 0, 255, 0, 255, 0, 0, 0, 0};

  const uint8_t kExpectNomask[12] = {0,   0, 255, 0,   255, 0,
                                     255, 0, 0,   128, 128, 128};
  uint8_t dst[12];

  RetainPtr<CPDF_ColorSpace> pCal = CPDF_ColorSpace::AllocateColorSpaceForID(
      nullptr, FXBSTR_ID('C', 'a', 'l', 'R'));
  ASSERT_TRUE(pCal);

  pCal->TranslateImageLine(dst, kSrc, 4, 4, 1, true);
  for (size_t i = 0; i < 12; ++i)
    EXPECT_EQ(dst[i], kExpectMask[i]) << " at " << i;

  pCal->TranslateImageLine(dst, kSrc, 4, 4, 1, false);
  for (size_t i = 0; i < 12; ++i)
    EXPECT_EQ(dst[i], kExpectNomask[i]) << " at " << i;
}
