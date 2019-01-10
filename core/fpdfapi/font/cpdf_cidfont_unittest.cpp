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
  EXPECT_EQ(31, font.GlyphFromCharCode(0, nullptr));
  EXPECT_EQ(34, font.GlyphFromCharCode(32, nullptr));
  EXPECT_EQ(88, font.GlyphFromCharCode(86, nullptr));
  EXPECT_EQ(229, font.GlyphFromCharCode(127, nullptr));
  EXPECT_EQ(186, font.GlyphFromCharCode(128, nullptr));
  EXPECT_EQ(286, font.GlyphFromCharCode(255, nullptr));
  EXPECT_EQ(287, font.GlyphFromCharCode(256, nullptr));
  EXPECT_EQ(34692, font.GlyphFromCharCode(34661, nullptr));
}
