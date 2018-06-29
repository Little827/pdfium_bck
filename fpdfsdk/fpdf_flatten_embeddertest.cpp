// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "public/fpdf_flatten.h"
#include "public/fpdf_ppo.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/test_support.h"

namespace {

class FPDFFlattenEmbeddertest : public EmbedderTest {};

#if _FX_PLATFORM_ == _FX_PLATFORM_APPLE_
const char kComboBoxFormMD5[] = "3f62a3c326c60a877b3d10d683942217";
#else
const char kComboBoxFormMD5[] = "d60d2553718030205f564297c126c83c";
#endif

struct FlattenTestData {
  const char* name;
  const char* md5;
  int width;
  int height;
} const kOnePageTests[] = {
    {"combobox_form", kComboBoxFormMD5, 300, 600},
    {"embedded_images", "a63036771e33c05c711abe8a758d6659", 612, 792},
    {"rectangles", "0a90de37f52127619c3dfb642b5fa2fe", 200, 300},
};

struct GetTestNameForFlattenTestData {
  std::string operator()(
      const testing::TestParamInfo<FlattenTestData>& info) const {
    return info.param.name;
  }
};

class FPDFFlattenEmbeddertestWithParam
    : public FPDFFlattenEmbeddertest,
      public testing::WithParamInterface<FlattenTestData> {};

}  // namespace

TEST_F(FPDFFlattenEmbeddertest, FlatNothing) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_NOTHINGTODO, FPDFPage_Flatten(page, FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbeddertest, FlatNormal) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbeddertest, FlatPrint) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_PRINT));
  UnloadPage(page);
}

TEST_P(FPDFFlattenEmbeddertestWithParam, ImportAndFlatPrint) {
  std::string name = GetParam().name;
  EXPECT_TRUE(OpenDocument(name + ".pdf"));
  int page_count = GetPageCount();
  ASSERT_EQ(1, page_count);

  {
    ScopedFPDFDocument output_doc(FPDF_CreateNewDocument());
    ASSERT_TRUE(FPDF_ImportPages(output_doc.get(), document(), "1", 0));
    EXPECT_EQ(1, FPDF_GetPageCount(output_doc.get()));
    ScopedFPDFPage page(FPDF_LoadPage(output_doc.get(), 0));
    EXPECT_NE(FLATTEN_FAIL, FPDFPage_Flatten(page.get(), FLAT_PRINT));
    EXPECT_TRUE(FPDF_SaveAsCopy(output_doc.get(), this, 0));
  }

  VerifySavedDocument(GetParam().width, GetParam().height, GetParam().md5);
}

INSTANTIATE_TEST_CASE_P(,
                        FPDFFlattenEmbeddertestWithParam,
                        testing::ValuesIn(kOnePageTests),
                        GetTestNameForFlattenTestData());
