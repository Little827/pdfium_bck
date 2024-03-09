// Copyright 2017 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_devicecs.h"

#include "core/fxcrt/retain_ptr.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(CPDF_DeviceCSTest, GetRGBFromGray) {
  std::optional<std::array<float, 3>> results;
  auto device_gray =
      pdfium::MakeRetain<CPDF_DeviceCS>(CPDF_ColorSpace::Family::kDeviceGray);

  // Test normal values. For gray, only first value from buf should be used.
  float buf[3] = {0.43f, 0.11f, 0.34f};
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.43f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.43f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.43f, results.value()[2]);
  buf[0] = 0.872f;
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.872f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.872f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.872f, results.value()[2]);

  // Test boundary values
  buf[0] = {0.0f};
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.0f, results.value()[2]);
  buf[0] = 1.0f;
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(1.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[2]);

  // Test out of range values
  buf[0] = -0.01f;
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.0f, results.value()[2]);
  buf[0] = 12.5f;
  results = device_gray->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(1.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[2]);
}

TEST(CPDF_DeviceCSTest, GetRGBFromRGB) {
  std::optional<std::array<float, 3>> results;
  auto device_rgb =
      pdfium::MakeRetain<CPDF_DeviceCS>(CPDF_ColorSpace::Family::kDeviceRGB);

  // Test normal values
  float buf[3] = {0.13f, 1.0f, 0.652f};
  results = device_rgb->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.13f, results.value()[0]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.652f, results.value()[2]);
  buf[0] = 0.0f;
  buf[1] = 0.52f;
  buf[2] = 0.78f;
  results = device_rgb->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.52f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.78f, results.value()[2]);

  // Test out of range values
  buf[0] = -10.5f;
  buf[1] = 100.0f;
  results = device_rgb->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.0f, results.value()[0]);
  EXPECT_FLOAT_EQ(1.0f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.78f, results.value()[2]);
}

TEST(CPDF_DeviceCSTest, GetRGBFromCMYK) {
  std::optional<std::array<float, 3>> results;
  auto device_cmyk =
      pdfium::MakeRetain<CPDF_DeviceCS>(CPDF_ColorSpace::Family::kDeviceCMYK);

  // Test normal values
  float buf[4] = {0.6f, 0.5f, 0.3f, 0.9f};
  results = device_cmyk->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.0627451f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.0627451f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.10588236f, results.value()[2]);
  buf[0] = 0.15f;
  buf[2] = 0.0f;
  results = device_cmyk->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.2f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.0862745f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.16470589f, results.value()[2]);
  buf[2] = 1.0f;
  buf[3] = 0.0f;
  results = device_cmyk->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.85098046f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.552941f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.15686275f, results.value()[2]);

  // Test out of range values
  buf[2] = 1.5f;
  buf[3] = -0.6f;
  results = device_cmyk->GetRGB(buf);
  ASSERT_TRUE(results.has_value());
  EXPECT_FLOAT_EQ(0.85098046f, results.value()[0]);
  EXPECT_FLOAT_EQ(0.552941f, results.value()[1]);
  EXPECT_FLOAT_EQ(0.15686275f, results.value()[2]);
}
