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
      "5 beginbfrange\n"
      // Legal bfrange
      "<0024> <0025> [ <0041> <0042> ]\n"
      // Illegal bfranges (the first-byte boundaries are crossed) in different
      // formats
      "<0AFE> <0B00> [ <20A0> <20A1> <20A2> ]\n"
      "<09FF> <0A00> <1E86>\n"
      // More Legal bfranges in different formats
      "<0013> <0019> <0030>\n"
      "<0020> <0020> [ <0037> ]\n"
      "endbfrange\n";

  auto stream = pdfium::MakeRetain<CPDF_Stream>();
  stream->InitStream(pdfium::as_bytes(pdfium::make_span(kBfRange)),
                     pdfium::MakeRetain<CPDF_Dictionary>());

  // During the construction of CPDF_ToUnicodeMap, CPDF_ToUnicodeMap::Load()
  // calls CPDF_ToUnicodeMap::HandleBeginBFRange().
  auto to_unicode_map = pdfium::MakeUnique<CPDF_ToUnicodeMap>(stream.Get());

  // Verify the charcode to unicode mappings with legal bfranges
  EXPECT_EQ(to_unicode_map->Lookup(0x0024), L"A");
  EXPECT_EQ(to_unicode_map->Lookup(0x0025), L"B");
  EXPECT_EQ(to_unicode_map->Lookup(0x0013), L"0");
  EXPECT_EQ(to_unicode_map->Lookup(0x0019), L"6");
  EXPECT_EQ(to_unicode_map->Lookup(0x0020), L"7");

  // Verify the mappings for charcodes within illegal bfrange are ignored
  for (uint32_t charcode = 0x0AFE; charcode <= 0x0B00; ++charcode) {
    EXPECT_TRUE(to_unicode_map->Lookup(charcode).IsEmpty());
  }
  for (uint32_t charcode = 0x09FF; charcode <= 0x0A00; ++charcode) {
    EXPECT_TRUE(to_unicode_map->Lookup(charcode).IsEmpty());
  }
}
