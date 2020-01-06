// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_folderfontinfo.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/base/ptr_util.h"
#include "third_party/base/stl_util.h"

namespace {
constexpr char kArial[] = "Arial";
constexpr char kTimesNewRoman[] = "TimesNewRoman";
constexpr char kSymbol[] = "Symbol";
constexpr char kBookshelfSymbol7[] = "Bookshelf Symbol 7";
constexpr char kCalibri[] = "Calibri";
constexpr char kBookshelf[] = "Bookshelf";
}  // namespace

class CFX_FolderFontInfoTest : public ::testing::Test {
 public:
  CFX_FolderFontInfoTest() {
    auto pArialInfo = pdfium::MakeUnique<CFX_FolderFontInfo::FontFaceInfo>(
        "" /*filePath*/, kArial /*faceName*/, "" /*fontTables*/,
        0 /*fontOffset*/, 0 /*fileSize*/);
    pArialInfo->m_Charsets = 2;
    auto pTimesNewRomanInfo =
        pdfium::MakeUnique<CFX_FolderFontInfo::FontFaceInfo>(
            "" /*filePath*/, kTimesNewRoman /*faceName*/, "" /*fontTables*/,
            0 /*fontOffset*/, 0 /*fileSize*/);
    auto pBookshelfSymbol7Info =
        pdfium::MakeUnique<CFX_FolderFontInfo::FontFaceInfo>(
            "" /*filePath*/, kBookshelfSymbol7 /*faceName*/, "" /*fontTables*/,
            0 /*fontOffset*/, 0 /*fileSize*/);
    pBookshelfSymbol7Info->m_Charsets = 2;
    auto pSymbolInfo = pdfium::MakeUnique<CFX_FolderFontInfo::FontFaceInfo>(
        "" /*filePath*/, kSymbol /*faceName*/, "" /*fontTables*/,
        0 /*fontOffset*/, 0 /*fileSize*/);
    pSymbolInfo->m_Charsets = 2;

    m_fontinfo.m_FontList[kArial] = std::move(pArialInfo);
    m_fontinfo.m_FontList[kTimesNewRoman] = std::move(pTimesNewRomanInfo);
    m_fontinfo.m_FontList[kBookshelfSymbol7] = std::move(pBookshelfSymbol7Info);
    m_fontinfo.m_FontList[kSymbol] = std::move(pSymbolInfo);
  }

  CFX_FolderFontInfo::FontFaceInfo* FindFont(int weight,
                                             bool bItalic,
                                             int charset,
                                             int pitch_family,
                                             const char* family,
                                             bool bMatchName) {
    return static_cast<CFX_FolderFontInfo::FontFaceInfo*>(m_fontinfo.FindFont(
        weight, bItalic, charset, pitch_family, family, bMatchName));
  }

 private:
  CFX_FolderFontInfo m_fontinfo;
};

TEST_F(CFX_FolderFontInfoTest, TestFindFont) {
  // Find "Symbol" font
  auto pFont =
      FindFont(0 /*weight*/, false /*bItalic*/, 2 /*charset*/,
               2 /*pitch_family*/, kSymbol /*family*/, true /*bMatchName*/);
  ASSERT_TRUE(pFont != nullptr);
  EXPECT_TRUE(pFont->m_FaceName == kSymbol);

  // Find "Calibri" font that is not present in the installed fonts
  EXPECT_TRUE(FindFont(0 /*weight*/, false /*bItalic*/, 2 /*charset*/,
                       2 /* pitch_family */, kCalibri /*family*/,
                       true /*bMatchName*/) == nullptr);

  // Find the closest matching font to "Bookself" font that is present in the
  // installed fonts
  pFont =
      FindFont(0 /*weight*/, false /*bItalic*/, 2 /*charset*/,
               2 /*pitch_family*/, kBookshelf /*family*/, true /*bMatchName*/);
  ASSERT_TRUE(pFont != nullptr);
  EXPECT_TRUE(pFont->m_FaceName == kBookshelfSymbol7);

  // Find "Symbol" font when name matching is false
  pFont =
      FindFont(0 /*weight*/, false /*bItalic*/, 2 /*charset*/,
               2 /*pitch_family*/, kSymbol /*family*/, false /*bMatchName*/);
  ASSERT_TRUE(pFont != nullptr);
  EXPECT_TRUE(pFont->m_FaceName == kArial);
}
