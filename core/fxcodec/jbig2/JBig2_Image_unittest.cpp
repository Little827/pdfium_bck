// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(tsepez) this requires a lot more testing.

#include <stdint.h>

#include "core/fxcodec/jbig2/JBig2_Image.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

const int32_t kWidthPixels = 80;
const int32_t kWidthBytes = 10;
const int32_t kStrideBytes = kWidthBytes + 1;  // For testing stride != width.
const int32_t kHeightLines = 20;
const int32_t kLargerHeightLines = 100;
const int32_t kTooLargeHeightLines = 40000000;

}  // namespace

TEST(fxcodec, EmptyImage) {
  CJBig2_Image empty(0, 0);
  EXPECT_EQ(empty.width(), 0);
  EXPECT_EQ(empty.height(), 0);

  // Out-of-bounds SetPixel() is silent no-op.
  empty.SetPixel(0, 0, true);
  empty.SetPixel(1, 1, true);

  // Out-of-bounds GetPixel returns 0.
  EXPECT_EQ(empty.GetPixel(0, 0), 0);
  EXPECT_EQ(empty.GetPixel(1, 1), 0);

  // Out-of-bounds GetLine() returs null.
  EXPECT_EQ(empty.GetLine(0), nullptr);
  EXPECT_EQ(empty.GetLine(1), nullptr);
}

TEST(fxcodec, JBig2ImageCreate) {
  CJBig2_Image img(kWidthPixels, kHeightLines);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kHeightLines, img.height());
  EXPECT_EQ(0, img.GetPixel(0, 0));
  EXPECT_EQ(0, img.GetLine(0)[0]);
  EXPECT_EQ(0, img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
  EXPECT_EQ(0, img.GetLine(kHeightLines - 1)[kWidthBytes - 1]);

  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, true);
  EXPECT_EQ(1, img.GetPixel(0, 0));
  EXPECT_EQ(1, img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
  EXPECT_EQ(0x80, img.GetLine(0)[0]);
  EXPECT_EQ(0x01, img.GetLine(kHeightLines - 1)[kWidthBytes - 1]);

  // Out-of-bounds SetPixel() is silent no-op.
  img.SetPixel(-1, 1, true);
  img.SetPixel(kWidthPixels, kHeightLines, true);

  // Out-of-bounds GetPixel returns 0.
  EXPECT_EQ(0, img.GetPixel(-1, -1));
  EXPECT_EQ(0, img.GetPixel(kWidthPixels, kHeightLines));

  // Out-of-bounds GetLine() returs null.
  EXPECT_EQ(nullptr, img.GetLine(-1));
  EXPECT_EQ(nullptr, img.GetLine(kHeightLines));
}

TEST(fxcodec, JBig2ImageCreateTooBig) {
  CJBig2_Image img(kWidthPixels, kTooLargeHeightLines);
  EXPECT_EQ(0, img.width());
  EXPECT_EQ(0, img.height());
  EXPECT_EQ(nullptr, img.data());
}

TEST(fxcodec, JBig2ImageCreateExternal) {
  uint8_t buf[kHeightLines * kStrideBytes];
  CJBig2_Image img(kWidthPixels, kHeightLines, kStrideBytes, buf);
  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, false);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kHeightLines, img.height());
  EXPECT_TRUE(img.GetPixel(0, 0));
  EXPECT_FALSE(img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
}

TEST(fxcodec, JBig2ImageCreateExternalTooBig) {
  uint8_t buf[kHeightLines * kStrideBytes];
  CJBig2_Image img(kWidthPixels, kTooLargeHeightLines, kStrideBytes, buf);
  EXPECT_EQ(0, img.width());
  EXPECT_EQ(0, img.height());
  EXPECT_EQ(nullptr, img.data());
}

TEST(fxcodec, JBig2ImageExpand) {
  CJBig2_Image img(kWidthPixels, kHeightLines);
  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, false);
  img.Expand(kLargerHeightLines, true);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kLargerHeightLines, img.height());
  EXPECT_TRUE(img.GetPixel(0, 0));
  EXPECT_FALSE(img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
  EXPECT_TRUE(img.GetPixel(kWidthPixels - 1, kLargerHeightLines - 1));
}

TEST(fxcodec, JBig2ImageExpandTooBig) {
  CJBig2_Image img(kWidthPixels, kHeightLines);
  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, false);
  img.Expand(kTooLargeHeightLines, true);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kHeightLines, img.height());
  EXPECT_TRUE(img.GetPixel(0, 0));
  EXPECT_FALSE(img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
}

TEST(fxcodec, JBig2ImageExpandExternal) {
  uint8_t buf[kHeightLines * kStrideBytes];
  CJBig2_Image img(kWidthPixels, kHeightLines, kStrideBytes, buf);
  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, false);
  img.Expand(kLargerHeightLines, true);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kLargerHeightLines, img.height());
  EXPECT_TRUE(img.GetPixel(0, 0));
  EXPECT_FALSE(img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
  EXPECT_TRUE(img.GetPixel(kWidthPixels - 1, kLargerHeightLines - 1));
}

TEST(fxcodec, JBig2ImageExpandExternalTooBig) {
  uint8_t buf[kHeightLines * kStrideBytes];
  CJBig2_Image img(kWidthPixels, kHeightLines, kStrideBytes, buf);
  img.SetPixel(0, 0, true);
  img.SetPixel(kWidthPixels - 1, kHeightLines - 1, false);
  img.Expand(kTooLargeHeightLines, true);
  EXPECT_EQ(kWidthPixels, img.width());
  EXPECT_EQ(kHeightLines, img.height());
  EXPECT_TRUE(img.GetPixel(0, 0));
  EXPECT_FALSE(img.GetPixel(kWidthPixels - 1, kHeightLines - 1));
}
