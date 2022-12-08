// Copyright 2016 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "core/fxcrt/fx_string.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/span.h"

char* TerminatedFloatToString(float value, pdfium::span<char> buf) {
  size_t buflen = FloatToString(value, buf);
  buf[buflen] = '\0';
  return buf.data();
}

char* TerminatedDoubleToString(double value, pdfium::span<char> buf) {
  size_t buflen = DoubleToString(value, buf);
  buf[buflen] = '\0';
  return buf.data();
}

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

TEST(fxstring, IsUTF8ByteStringForStructurallyValidUtf8) {
  EXPECT_TRUE(FX_IsUTF8ByteString("abc"));
  EXPECT_TRUE(FX_IsUTF8ByteString("\xC2\x81"));
  EXPECT_TRUE(FX_IsUTF8ByteString("\xE1\x80\xBF"));
  EXPECT_TRUE(FX_IsUTF8ByteString("\xF1\x80\xA0\xBF"));
  EXPECT_TRUE(FX_IsUTF8ByteString("\xF1\x80\xA0\xBF"));
  EXPECT_TRUE(FX_IsUTF8ByteString("a\xC2\x81\xE1\x80\xBF\xF1\x80\xA0\xBF"));

  // U+FEFF used as UTF-8 BOM.
  // clang-format off
  EXPECT_TRUE(FX_IsUTF8ByteString("\xEF\xBB\xBF" "abc"));
  // clang-format on

  // Embedded nulls in canonical UTF-8 representation.
  const char kEmbeddedNull[] = "embedded\0null";
  EXPECT_TRUE(FX_IsUTF8ByteString(
      ByteStringView(kEmbeddedNull, sizeof(kEmbeddedNull) - 1)));

  const char kPrunedOfUTF8Chars[] = " a b c ";
  const char kNoCharsLeftOnlySpaces[] = "  ";
  EXPECT_TRUE(FX_IsUTF8ByteString(kPrunedOfUTF8Chars));
  EXPECT_TRUE(FX_IsUTF8ByteString(kNoCharsLeftOnlySpaces));
}

TEST(fxstring, IsUTF8ByteStringForStructurallyInvalidUtf8) {
  // Invalid encoding of U+1FFFE (0x8F instead of 0x9F)
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF0\x8F\xBF\xBE"));

  // Surrogate code points
  EXPECT_FALSE(FX_IsUTF8ByteString("\xED\xA0\x80\xED\xBF\xBF"));
  EXPECT_FALSE(FX_IsUTF8ByteString("\xED\xA0\x8F"));
  EXPECT_FALSE(FX_IsUTF8ByteString("\xED\xBF\xBF"));

  // Overlong sequences
  EXPECT_FALSE(FX_IsUTF8ByteString("\xC0\x80"));                  // U+0000
  EXPECT_FALSE(FX_IsUTF8ByteString("\xC1\x80\xC1\x81"));          // "AB"
  EXPECT_FALSE(FX_IsUTF8ByteString("\xE0\x80\x80"));              // U+0000
  EXPECT_FALSE(FX_IsUTF8ByteString("\xE0\x82\x80"));              // U+0080
  EXPECT_FALSE(FX_IsUTF8ByteString("\xE0\x9F\xBF"));              // U+07FF
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF0\x80\x80\x8D"));          // U+000D
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF0\x80\x82\x91"));          // U+0091
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF0\x80\xA0\x80"));          // U+0800
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF0\x8F\xBB\xBF"));          // U+FEFF BOM
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF8\x80\x80\x80\xBF"));      // U+003F
  EXPECT_FALSE(FX_IsUTF8ByteString("\xFC\x80\x80\x80\xA0\xA5"));  // U+00A5

  // Beyond U+10FFFF (the upper limit of Unicode codespace)
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF4\x90\x80\x80"));          // U+110000
  EXPECT_FALSE(FX_IsUTF8ByteString("\xF8\xA0\xBF\x80\xBF"));      // 5 bytes
  EXPECT_FALSE(FX_IsUTF8ByteString("\xFC\x9C\xBF\x80\xBF\x80"));  // 6 bytes

  // BOM in UTF-16(BE|LE)
  EXPECT_FALSE(FX_IsUTF8ByteString("\xFE\xFF"));
  EXPECT_FALSE(FX_IsUTF8ByteString("\xFF\xFE"));

  // Strings in legacy encodings. We can certainly make up strings
  // in a legacy encoding that are valid in UTF-8, but in real data,
  // most of them are invalid as UTF-8.

  // cafe with U+00E9 in ISO-8859-1
  EXPECT_FALSE(FX_IsUTF8ByteString("caf\xE9"));
  // U+AC00, U+AC001 in EUC-KR
  EXPECT_FALSE(FX_IsUTF8ByteString("\xB0\xA1\xB0\xA2"));
  // U+4F60 U+597D in Big5
  EXPECT_FALSE(FX_IsUTF8ByteString("\xA7\x41\xA6\x6E"));
  // "abc" with U+201[CD] in windows-125[0-8]
  // clang-format off
  EXPECT_FALSE(FX_IsUTF8ByteString("\x93" "abc\x94"));
  // clang-format on
  // U+0639 U+064E U+0644 U+064E in ISO-8859-6
  EXPECT_FALSE(FX_IsUTF8ByteString("\xD9\xEE\xE4\xEE"));
  // U+03B3 U+03B5 U+03B9 U+03AC in ISO-8859-7
  EXPECT_FALSE(FX_IsUTF8ByteString("\xE3\xE5\xE9\xDC"));

  // BOM in UTF-32(BE|LE)
  const char kUtf32BeBom[] = "\x00\x00\xFE\xFF";
  EXPECT_FALSE(FX_IsUTF8ByteString(
      ByteStringView(kUtf32BeBom, sizeof(kUtf32BeBom) - 1)));
  const char kUtf32LeBom[] = "\xFF\xFE\x00\x00";
  EXPECT_FALSE(FX_IsUTF8ByteString(
      ByteStringView(kUtf32LeBom, sizeof(kUtf32LeBom) - 1)));

  const char kInvalidContinuation1[] = "a(\xc2\x41)";
  const char kInvalidContinuation2[] = "b(\xc2\xc2)";
  const char kInvalidContinuation3[] = "c(\xc2\xff\x80)";
  const char kInvalidLeading1[] = "d(\x80\x80)";
  const char kInvalidLeading2[] = "e(\xff\x80\x80)";
  EXPECT_FALSE(FX_IsUTF8ByteString(kInvalidContinuation1));
  EXPECT_FALSE(FX_IsUTF8ByteString(kInvalidContinuation2));
  EXPECT_FALSE(FX_IsUTF8ByteString(kInvalidContinuation3));
  EXPECT_FALSE(FX_IsUTF8ByteString(kInvalidLeading1));
  EXPECT_FALSE(FX_IsUTF8ByteString(kInvalidLeading2));

  const char kSomeInvalidUTF8Chars[] = " a\x80 b\x80 c ";
  const char kStartWithInvalidUTF8Char[] = "\x80 a b c ";
  const char kEndWithInvalidUTF8Chars[] = " a b c\x80 ";
  const char kOnlyInvalidUTF8Chars[] = "\x80 \x80 ";
  const char kSingleInvalidUTF8Char[] = "\xf1";
  EXPECT_FALSE(FX_IsUTF8ByteString(kSomeInvalidUTF8Chars));
  EXPECT_FALSE(FX_IsUTF8ByteString(kStartWithInvalidUTF8Char));
  EXPECT_FALSE(FX_IsUTF8ByteString(kEndWithInvalidUTF8Chars));
  EXPECT_FALSE(FX_IsUTF8ByteString(kOnlyInvalidUTF8Chars));
  EXPECT_FALSE(FX_IsUTF8ByteString(kSingleInvalidUTF8Char));
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

TEST(fxstring, ByteStringToFloat) {
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

TEST(fxstring, WideStringToFloat) {
  EXPECT_FLOAT_EQ(0.0f, StringToFloat(L""));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat(L"0"));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat(L"0.0"));
  EXPECT_FLOAT_EQ(0.0f, StringToFloat(L"-0.0"));

  EXPECT_FLOAT_EQ(0.25f, StringToFloat(L"0.25"));
  EXPECT_FLOAT_EQ(-0.25f, StringToFloat(L"-0.25"));

  EXPECT_FLOAT_EQ(100.0f, StringToFloat(L"100"));
  EXPECT_FLOAT_EQ(100.0f, StringToFloat(L"100.0"));
  EXPECT_FLOAT_EQ(100.0f, StringToFloat(L"    100.0"));
  EXPECT_FLOAT_EQ(-100.0f, StringToFloat(L"-100.0000"));

  EXPECT_FLOAT_EQ(3.402823e+38f,
                  StringToFloat(L"340282300000000000000000000000000000000"));
  EXPECT_FLOAT_EQ(-3.402823e+38f,
                  StringToFloat(L"-340282300000000000000000000000000000000"));

  EXPECT_FLOAT_EQ(1.000000119f, StringToFloat(L"1.000000119"));
  EXPECT_FLOAT_EQ(1.999999881f, StringToFloat(L"1.999999881"));
}

TEST(fxstring, FloatToString) {
  char buf[32];

  EXPECT_STREQ("0", TerminatedFloatToString(0.0f, buf));
  EXPECT_STREQ("0", TerminatedFloatToString(-0.0f, buf));
  EXPECT_STREQ("0",
               TerminatedFloatToString(std::numeric_limits<float>::min(), buf));
  EXPECT_STREQ(
      "0", TerminatedFloatToString(-std::numeric_limits<float>::min(), buf));

  EXPECT_STREQ("0.25", TerminatedFloatToString(0.25f, buf));
  EXPECT_STREQ("-0.25", TerminatedFloatToString(-0.25f, buf));

  EXPECT_STREQ("100", TerminatedFloatToString(100.0f, buf));
  EXPECT_STREQ("-100", TerminatedFloatToString(-100.0f, buf));

  // FloatToString won't convert beyond the maximum integer, and values
  // larger than that get converted to a string representing that.
  EXPECT_STREQ("2147483647", TerminatedFloatToString(2147483647.0f, buf));
  EXPECT_STREQ("2147483647", TerminatedFloatToString(2147483647.5f, buf));
  EXPECT_STREQ("2147483647",
               TerminatedFloatToString(std::numeric_limits<float>::max(), buf));

  // FloatToString won't convert beyond the minimum integer, and values
  // smaller than that get converted to a string representing that.
  EXPECT_STREQ("-2147483647", TerminatedFloatToString(-2147483647.0f, buf));
  EXPECT_STREQ("-2147483647", TerminatedFloatToString(-2147483647.5f, buf));
  EXPECT_STREQ("-2147483647", TerminatedFloatToString(
                                  -std::numeric_limits<float>::max(), buf));

  // Conversion only acknowledges precision to 5 digit past decimal, and
  // rounds beyond that.
  EXPECT_STREQ("1", TerminatedFloatToString(1.000001119f, buf));
  EXPECT_STREQ("1.00001", TerminatedFloatToString(1.000011119f, buf));
  EXPECT_STREQ("1.99999", TerminatedFloatToString(1.999988881f, buf));
  EXPECT_STREQ("2", TerminatedFloatToString(1.999999881f, buf));
}

TEST(fxstring, ByteStringToDouble) {
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

TEST(fxstring, WideStringToDouble) {
  EXPECT_FLOAT_EQ(0.0, StringToDouble(L""));
  EXPECT_FLOAT_EQ(0.0, StringToDouble(L"0"));
  EXPECT_FLOAT_EQ(0.0, StringToDouble(L"0.0"));
  EXPECT_FLOAT_EQ(0.0, StringToDouble(L"-0.0"));

  EXPECT_FLOAT_EQ(0.25, StringToDouble(L"0.25"));
  EXPECT_FLOAT_EQ(-0.25, StringToDouble(L"-0.25"));

  EXPECT_FLOAT_EQ(100.0, StringToDouble(L"100"));
  EXPECT_FLOAT_EQ(100.0, StringToDouble(L"100.0"));
  EXPECT_FLOAT_EQ(100.0, StringToDouble(L"    100.0"));
  EXPECT_FLOAT_EQ(-100.0, StringToDouble(L"-100.0000"));

  EXPECT_FLOAT_EQ(3.402823e+38,
                  StringToDouble(L"340282300000000000000000000000000000000"));
  EXPECT_FLOAT_EQ(-3.402823e+38,
                  StringToDouble(L"-340282300000000000000000000000000000000"));

  EXPECT_FLOAT_EQ(1.000000119, StringToDouble(L"1.000000119"));
  EXPECT_FLOAT_EQ(1.999999881, StringToDouble(L"1.999999881"));
}

TEST(fxstring, DoubleToString) {
  char buf[32];

  EXPECT_STREQ("0", TerminatedDoubleToString(0.0f, buf));
  EXPECT_STREQ("0", TerminatedDoubleToString(-0.0f, buf));
  EXPECT_STREQ(
      "0", TerminatedDoubleToString(std::numeric_limits<double>::min(), buf));
  EXPECT_STREQ(
      "0", TerminatedDoubleToString(-std::numeric_limits<double>::min(), buf));

  EXPECT_STREQ("0.25", TerminatedDoubleToString(0.25f, buf));
  EXPECT_STREQ("-0.25", TerminatedDoubleToString(-0.25f, buf));

  EXPECT_STREQ("100", TerminatedDoubleToString(100.0f, buf));
  EXPECT_STREQ("-100", TerminatedDoubleToString(-100.0f, buf));

  // DoubleToString won't convert beyond the maximum integer, and values
  // larger than that get converted to a string representing that.
  EXPECT_STREQ("2147483647", TerminatedDoubleToString(2147483647.0f, buf));
  EXPECT_STREQ("2147483647", TerminatedDoubleToString(2147483647.5f, buf));
  EXPECT_STREQ("2147483647", TerminatedDoubleToString(
                                 std::numeric_limits<double>::max(), buf));

  // DoubleToString won't convert beyond the minimum integer, and values
  // smaller than that get converted to a string representing that.
  EXPECT_STREQ("-2147483647", TerminatedDoubleToString(-2147483647.0f, buf));
  EXPECT_STREQ("-2147483647", TerminatedDoubleToString(-2147483647.5f, buf));
  EXPECT_STREQ("-2147483647", TerminatedDoubleToString(
                                  -std::numeric_limits<double>::max(), buf));

  // Conversion only acknowledges precision to 5 digit past decimal, and
  // rounds beyond that.
  EXPECT_STREQ("1", TerminatedDoubleToString(1.000001119f, buf));
  EXPECT_STREQ("1.00001", TerminatedDoubleToString(1.000011119f, buf));
  EXPECT_STREQ("1.99999", TerminatedDoubleToString(1.999988881f, buf));
  EXPECT_STREQ("2", TerminatedDoubleToString(1.999999881f, buf));
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
