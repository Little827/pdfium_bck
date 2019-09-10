// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/fx_string.h"
#include "testing/gtest/include/gtest/gtest.h"

TEST(fxstring, FX_UTF8Encode) {
  EXPECT_EQ("", FX_UTF8Encode(WideStringView()));
  EXPECT_EQ(
      "x"
      "\xc2\x80"
      "\xc3\xbf"
      "\xef\xbc\xac"
      "y",
      FX_UTF8Encode(L"x"
                    L"\u0080"
                    L"\u00ff"
                    L"\uff2c"
                    L"y"));
}

TEST(fxstring, FX_UTF8Decode) {
  EXPECT_EQ(L"", FX_UTF8Decode(ByteStringView()));
  EXPECT_EQ(
      L"x"
      L"\u0080"
      L"\u00ff"
      L"\uff2c"
      L"y",
      FX_UTF8Decode("x"
                    "\xc2\x80"
                    "\xc3\xbf"
                    "\xef\xbc\xac"
                    "y"));
  EXPECT_EQ(L"a(A) b() c() d() e().",
            FX_UTF8Decode("a(\xc2\x41) "      // Invalid continuation.
                          "b(\xc2\xc2) "      // Invalid continuation.
                          "c(\xc2\xff\x80) "  // Invalid continuation.
                          "d(\x80\x80) "      // Invalid leading.
                          "e(\xff\x80\x80)"   // Invalid leading.
                          "."));
}

TEST(fxstring, FX_UTF8EncodeDecodeConsistency) {
  WideString wstr;
  wstr.Reserve(0x10000);
  for (int w = 0; w < 0x10000; ++w)
    wstr += static_cast<wchar_t>(w);

  ByteString bstr = FX_UTF8Encode(wstr.AsStringView());
  WideString wstr2 = FX_UTF8Decode(bstr.AsStringView());
  EXPECT_EQ(0x10000u, wstr2.GetLength());
  EXPECT_EQ(wstr, wstr2);
}

TEST(fxstring, StringToFloat) {
  EXPECT_FLOAT_EQ(0.0f, StringToFloat(""));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat("0"));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat("0.0"));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat("-0.0"));

  EXPECT_FLOAT_EQ(0.25f, StringToFloat("0.25"));
  EXPECT_FLOAT_EQ(-0.25f, StringToFloat("-0.25"));

  EXPECT_FLOAT_EQ(100.0f, StringToFloat("100"));
  EXPECT_FLOAT_EQ(100.0f, StringToFloat("100.0"));
  EXPECT_FLOAT_EQ(100.0f, StringToFloat("    100.0"));
  EXPECT_FLOAT_EQ(-100.0f, StringToFloat("-100.0000"));

  EXPECT_FLOAT_EQ(3.402823e+38f,
                  StringToFloat("340282300000000000000000000000000000000"));
  EXPECT_FLOAT_EQ(-3.402823e+38f,
                  StringToFloat("-340282300000000000000000000000000000000"));

  EXPECT_FLOAT_EQ(1.000000119f, StringToFloat("1.000000119"));
  EXPECT_FLOAT_EQ(1.999999881f, StringToFloat("1.999999881"));
}

TEST(fxstring, FloatToString) {
  size_t buflen;
  char buf[256];

  buflen = FloatToString(0.0f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("0", buf);

  buflen = FloatToString(0.25f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("0.25", buf);
  buflen = FloatToString(-0.25f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-0.25", buf);

  buflen = FloatToString(100.0f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("100", buf);
  buflen = FloatToString(-100.0f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-100", buf);

  // FloatToString won't convert beyond the maximum integer, and values
  // larger than that get converted to a string representing that.
  buflen = FloatToString(3.402823e+38f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("2147483647", buf);

  // FloatToString won't convert beyond the minimum integer, and values
  // smaller than that get converted to a string representing that.
  buflen = FloatToString(-3.402823e+38f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-2147483647", buf);

  // Conversion only acknowledges precision to 5 digit past decimal, and
  // rounds beyond that.
  buflen = FloatToString(1.000001119f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1", buf);
  buflen = FloatToString(1.000011119f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1.00001", buf);
  buflen = FloatToString(1.999988881f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1.99999", buf);
  buflen = FloatToString(1.999999881f, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("2", buf);
}

TEST(fxstring, StringToDouble) {
  EXPECT_FLOAT_EQ(0.0, StringToDouble(""));
  EXPECT_FLOAT_EQ(0.0, StringToDouble("0"));
  EXPECT_FLOAT_EQ(0.0, StringToDouble("0.0"));
  EXPECT_FLOAT_EQ(0.0, StringToDouble("-0.0"));

  EXPECT_FLOAT_EQ(0.25, StringToDouble("0.25"));
  EXPECT_FLOAT_EQ(-0.25, StringToDouble("-0.25"));

  EXPECT_FLOAT_EQ(100.0, StringToDouble("100"));
  EXPECT_FLOAT_EQ(100.0, StringToDouble("100.0"));
  EXPECT_FLOAT_EQ(100.0, StringToDouble("    100.0"));
  EXPECT_FLOAT_EQ(-100.0, StringToDouble("-100.0000"));

  EXPECT_FLOAT_EQ(3.402823e+38,
                  StringToDouble("340282300000000000000000000000000000000"));
  EXPECT_FLOAT_EQ(-3.402823e+38,
                  StringToDouble("-340282300000000000000000000000000000000"));

  EXPECT_FLOAT_EQ(1.000000119, StringToDouble("1.000000119"));
  EXPECT_FLOAT_EQ(1.999999881, StringToDouble("1.999999881"));
}

TEST(fxstring, DoubleToString) {
  size_t buflen;
  char buf[256];

  buflen = DoubleToString(0.0, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("0", buf);

  buflen = DoubleToString(0.25, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("0.25", buf);
  buflen = DoubleToString(-0.25, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-0.25", buf);

  buflen = DoubleToString(100.0, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("100", buf);
  buflen = DoubleToString(-100.0, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-100", buf);

  // DoubleToString won't convert beyond the maximum integer, and values
  // larger than that get converted to a string representing that.
  buflen = DoubleToString(3.402823e+38, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("2147483647", buf);

  // DoubleToString won't convert beyond the minimum integer, and values
  // smaller than that get converted to a string representing that.
  buflen = DoubleToString(-3.402823e+38, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("-2147483647", buf);

  // Conversion only acknowledges precision to 5 digit past decimal, and
  // rounds beyond that.
  buflen = DoubleToString(1.000001119, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1", buf);
  buflen = DoubleToString(1.000011119, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1.00001", buf);
  buflen = DoubleToString(1.999988881, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("1.99999", buf);
  buflen = DoubleToString(1.999999881, buf);
  buf[buflen] = '\0';
  EXPECT_STREQ("2", buf);
}

TEST(fxstring, SplitByteString) {
  std::vector<ByteString> result;
  result = fxcrt::Split(ByteString(""), ',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ("", result[0]);

  result = fxcrt::Split(ByteString("a"), ',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ("a", result[0]);

  result = fxcrt::Split(ByteString(","), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("", result[1]);

  result = fxcrt::Split(ByteString("a,"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("", result[1]);

  result = fxcrt::Split(ByteString(",b"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("b", result[1]);

  result = fxcrt::Split(ByteString("a,b"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("b", result[1]);

  result = fxcrt::Split(ByteString("a,b,"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("b", result[1]);
  EXPECT_EQ("", result[2]);

  result = fxcrt::Split(ByteString("a,,"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("", result[1]);
  EXPECT_EQ("", result[2]);

  result = fxcrt::Split(ByteString(",,a"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("", result[1]);
  EXPECT_EQ("a", result[2]);
}

TEST(fxstring, SplitByteStringView) {
  std::vector<ByteStringView> result;
  result = fxcrt::Split(ByteStringView(""), ',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ("", result[0]);

  result = fxcrt::Split(ByteStringView("a"), ',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ("a", result[0]);

  result = fxcrt::Split(ByteStringView(","), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("", result[1]);

  result = fxcrt::Split(ByteStringView("a,"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("", result[1]);

  result = fxcrt::Split(ByteStringView(",b"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("b", result[1]);

  result = fxcrt::Split(ByteStringView("a,b"), ',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("b", result[1]);

  result = fxcrt::Split(ByteStringView("a,b,"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("b", result[1]);
  EXPECT_EQ("", result[2]);

  result = fxcrt::Split(ByteStringView("a,,"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("a", result[0]);
  EXPECT_EQ("", result[1]);
  EXPECT_EQ("", result[2]);

  result = fxcrt::Split(ByteStringView(",,a"), ',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ("", result[0]);
  EXPECT_EQ("", result[1]);
  EXPECT_EQ("a", result[2]);
}

TEST(fxstring, SplitWideString) {
  std::vector<WideString> result;
  result = fxcrt::Split(WideString(L""), L',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ(L"", result[0]);

  result = fxcrt::Split(WideString(L"a"), L',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ(L"a", result[0]);

  result = fxcrt::Split(WideString(L","), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"", result[1]);

  result = fxcrt::Split(WideString(L"a,"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"", result[1]);

  result = fxcrt::Split(WideString(L",b"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"b", result[1]);

  result = fxcrt::Split(WideString(L"a,b"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"b", result[1]);

  result = fxcrt::Split(WideString(L"a,b,"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"b", result[1]);
  EXPECT_EQ(L"", result[2]);

  result = fxcrt::Split(WideString(L"a,,"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"", result[1]);
  EXPECT_EQ(L"", result[2]);

  result = fxcrt::Split(WideString(L",,a"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"", result[1]);
  EXPECT_EQ(L"a", result[2]);
}

TEST(fxstring, SplitWideStringView) {
  std::vector<WideStringView> result;
  result = fxcrt::Split(WideStringView(L""), L',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ(L"", result[0]);

  result = fxcrt::Split(WideStringView(L"a"), L',');
  ASSERT_EQ(1u, result.size());
  EXPECT_EQ(L"a", result[0]);

  result = fxcrt::Split(WideStringView(L","), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"", result[1]);

  result = fxcrt::Split(WideStringView(L"a,"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"", result[1]);

  result = fxcrt::Split(WideStringView(L",b"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"b", result[1]);

  result = fxcrt::Split(WideStringView(L"a,b"), L',');
  ASSERT_EQ(2u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"b", result[1]);

  result = fxcrt::Split(WideStringView(L"a,b,"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"b", result[1]);
  EXPECT_EQ(L"", result[2]);

  result = fxcrt::Split(WideStringView(L"a,,"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"a", result[0]);
  EXPECT_EQ(L"", result[1]);
  EXPECT_EQ(L"", result[2]);

  result = fxcrt::Split(WideStringView(L",,a"), L',');
  ASSERT_EQ(3u, result.size());
  EXPECT_EQ(L"", result[0]);
  EXPECT_EQ(L"", result[1]);
  EXPECT_EQ(L"a", result[2]);
}

TEST(fxstring, ByteStringSplitEfficiency) {
  std::vector<char> commas(50000, ',');
  ByteString input(commas.data(), commas.size());
  std::vector<ByteString> result;
  result = fxcrt::Split(input, ',');
  ASSERT_EQ(commas.size() + 1, result.size());
  EXPECT_EQ("", result.front());
  EXPECT_EQ("", result.back());
}

TEST(fxstring, ByteStringViewSplitEfficiency) {
  std::vector<char> commas(50000, ',');
  ByteStringView input(commas.data(), commas.size());
  std::vector<ByteStringView> result;
  result = fxcrt::Split(input, ',');
  ASSERT_EQ(commas.size() + 1, result.size());
  EXPECT_EQ("", result.front());
  EXPECT_EQ("", result.back());
}

TEST(fxstring, WideStringSplitEfficiency) {
  std::vector<wchar_t> commas(50000, L',');
  WideString input(commas.data(), commas.size());
  std::vector<WideString> result;
  result = fxcrt::Split(input, ',');
  ASSERT_EQ(commas.size() + 1, result.size());
  EXPECT_EQ(L"", result.front());
  EXPECT_EQ(L"", result.back());
}

TEST(fxstring, WideStringViewSplitEfficiency) {
  std::vector<wchar_t> commas(50000, L',');
  WideStringView input(commas.data(), commas.size());
  std::vector<WideStringView> result;
  result = fxcrt::Split(input, ',');
  ASSERT_EQ(commas.size() + 1, result.size());
  EXPECT_EQ(L"", result.front());
  EXPECT_EQ(L"", result.back());
}
