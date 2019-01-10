// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/font/cpdf_cidfont.h"

#include <utility>

#include "core/fpdfapi/cpdf_modulemgr.h"
#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_name.h"
#include "testing/gtest/include/gtest/gtest.h"

class CPDF_CIDFontTest : public testing::Test {
 protected:
  void SetUp() override { CPDF_ModuleMgr::Get()->Init(); }

  void TearDown() override { CPDF_ModuleMgr::Destroy(); }
};

TEST_F(CPDF_CIDFontTest, BUG_920636) {
  CPDF_Document doc;
  CPDF_Dictionary font_dict;
  font_dict.SetNewFor<CPDF_Name>("Encoding", "Identity−H");

  {
    auto descendant_fonts = pdfium::MakeUnique<CPDF_Array>();
    {
      auto descendant_font = pdfium::MakeUnique<CPDF_Dictionary>();
      descendant_font->SetNewFor<CPDF_Name>("BaseFont", "CourierStd");
      descendant_fonts->Add(std::move(descendant_font));
    }
    font_dict.SetFor("DescendantFonts", std::move(descendant_fonts));
  }

  CPDF_CIDFont font(&doc, &font_dict);
  ASSERT_TRUE(font.Load());

  static constexpr uint32_t kCharcodes[] = {0,   32,  86,  127,
                                            128, 255, 256, 34661};
#if _FX_PLATFORM_ == _FX_PLATFORM_WINDOWS_
  static constexpr int kGlyphs[] = {31, 3, 57, -1, 188, 185, 287, 34692};
#else
  static constexpr int kGlyphs[] = {31, 34, 88, 229, 186, 286, 287, 34692};
#endif
  static_assert(FX_ArraySize(kCharcodes) == FX_ArraySize(kGlyphs),
                "size mismatch");

  for (size_t i = 0; i < FX_ArraySize(kCharcodes); ++i)
    EXPECT_EQ(kGlyphs[i], font.GlyphFromCharCode(kCharcodes[i], nullptr));
}
