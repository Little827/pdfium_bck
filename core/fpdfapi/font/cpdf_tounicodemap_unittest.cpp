// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "core/fpdfapi/font/cpdf_tounicodemap.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_stream.h"

#include "testing/gtest/include/gtest/gtest.h"

TEST(cpdf_tounicodemap, StringToCode) {
  EXPECT_EQ(0u, CPDF_ToUnicodeMap::StringToCode(""));
  EXPECT_EQ(194u, CPDF_ToUnicodeMap::StringToCode("<c2"));
  EXPECT_EQ(162u, CPDF_ToUnicodeMap::StringToCode("<A2"));
  EXPECT_EQ(2802u, CPDF_ToUnicodeMap::StringToCode("<Af2"));
  EXPECT_EQ(12u, CPDF_ToUnicodeMap::StringToCode("12"));
  EXPECT_EQ(128u, CPDF_ToUnicodeMap::StringToCode("128"));
}

TEST(cpdf_tounicodemap, StringToWideString) {
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString(""));
  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString("1234"));

  EXPECT_EQ(L"", CPDF_ToUnicodeMap::StringToWideString("<c2"));

  WideString res = L"\xc2ab";
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2ab"));
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2abab"));
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2ab 1234"));

  res += L"\xfaab";
  EXPECT_EQ(res, CPDF_ToUnicodeMap::StringToWideString("<c2abFaAb"));
}

TEST(cpdf_tounicodemap, HandleBeginBFRange) {
  static constexpr char kBfRange[] =
      "99 beginbfrange\n"
      // Legal bfrange
      "<0013> <002F> [ <0030> <0031> <0032> <0033> <0034> <0035> <0036> <0037> "
      "<0038> <0039> <003A> <003B> <003C> <003D> <003E> <003F> <0040> <0041> "
      "<0042> <0043> <0044> <0045> <0046> <0047> <0048> <0049> <004A> <004B> "
      "<004C> ]\n"
      // Illegal bfranges (the first-byte boundaries are crossed)
      "<09FF> <0A14> [ <1E86> <1E87> <1E88> <1E89> <1E8A> <1E8B> <1E8C> <1E8D> "
      "<1E8E> <1E8F> <1E90> <1E91> <1E92> <1E93> <1E94> <1E95> <1E96> <1E97> "
      "<1E98> <1E99> <1E9A> <1E9B>]\n"
      "<0AFE> <0B00> [ <20A0> <20A1> <20A2> ]\n"
      "endbfrange\n";

  auto stream = pdfium::MakeRetain<CPDF_Stream>();
  stream->InitStream(pdfium::as_bytes(pdfium::make_span(kBfRange)),
                     pdfium::MakeRetain<CPDF_Dictionary>());

  // During the construction of CPDF_ToUnicodeMap, CPDF_ToUnicodeMap::Load()
  // calls CPDF_ToUnicodeMap::HandleBeginBFRange().
  auto to_unicode_map = pdfium::MakeUnique<CPDF_ToUnicodeMap>(stream.Get());

  // Verify the charcode to unicode mappings in the legal bfrange
  EXPECT_EQ(to_unicode_map->Lookup(0x00000013), L"0");
  EXPECT_EQ(to_unicode_map->Lookup(0x00000024), L"A");
  EXPECT_EQ(to_unicode_map->Lookup(0x0000002F), L"L");

  // Verify the mappings for charcodes within illegal bfrange are ignored
  for (uint32_t charcode = 0x000009ff; charcode <= 0x00000a14; ++charcode) {
    ASSERT_TRUE(to_unicode_map->Lookup(charcode).IsEmpty());
  }
  for (uint32_t charcode = 0x00000afe; charcode <= 0x00000b00; ++charcode) {
    ASSERT_TRUE(to_unicode_map->Lookup(charcode).IsEmpty());
  }
}
