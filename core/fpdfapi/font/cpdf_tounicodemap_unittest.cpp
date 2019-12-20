// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/font/cpdf_tounicodemap.h"

#include "testing/gtest/include/gtest/gtest.h"

TEST(cpdf_tounicodemap, StringToCode) {
  EXPECT_EQ(1u, CPDF_ToUnicodeMap::StringToCode("<0001>"));
  EXPECT_EQ(194u, CPDF_ToUnicodeMap::StringToCode("<c2>"));
  EXPECT_EQ(162u, CPDF_ToUnicodeMap::StringToCode("<A2>"));
  EXPECT_EQ(2802u, CPDF_ToUnicodeMap::StringToCode("<Af2>"));
  EXPECT_EQ(4294967295u, CPDF_ToUnicodeMap::StringToCode("<FFFFFFFF>"));

  // Integer overflow
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<100000000>"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<1abcdFFFF>"));

  // Invalid string
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode(""));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<>"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("128"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<12"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("12>"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<1-7>"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("00AB"));
  ASSERT_FALSE(CPDF_ToUnicodeMap::StringToCode("<00NN>"));
}

TEST(cpdf_tounicodemap, StringToWideString) {
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString(""));
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString("1234"));
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString("<c2D2"));
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString("c2ab>"));

  WideString res = L"\xc2ab";
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2ab>"));
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2ab123>"));
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2abX123>"));

  res += L"\xfaab";
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2abFaAb>"));
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2abFaAb12>"));
}
