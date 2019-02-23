// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include "core/fxcrt/fx_string.h"
#include "public/cpp/fpdf_scopers.h"
#include "public/fpdf_edit.h"
#include "public/fpdf_ppo.h"
#include "public/fpdf_save.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"

class FPDFSaveEmbedderTest : public EmbedderTest {};

TEST_F(FPDFSaveEmbedderTest, SaveSimpleDoc) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.7\r\n"));
  EXPECT_EQ(805u, GetString().length());
}

TEST_F(FPDFSaveEmbedderTest, SaveSimpleDocWithVersion) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  EXPECT_TRUE(FPDF_SaveWithVersion(document(), this, 0, 14));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.4\r\n"));
  EXPECT_EQ(805u, GetString().length());
}
TEST_F(FPDFSaveEmbedderTest, SaveSimpleDocWithBadVersion) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  EXPECT_TRUE(FPDF_SaveWithVersion(document(), this, 0, -1));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.7\r\n"));

  ClearString();
  EXPECT_TRUE(FPDF_SaveWithVersion(document(), this, 0, 0));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.7\r\n"));

  ClearString();
  EXPECT_TRUE(FPDF_SaveWithVersion(document(), this, 0, 18));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.7\r\n"));
}

TEST_F(FPDFSaveEmbedderTest, SaveCopiedDoc) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);

  FPDF_DOCUMENT output_doc = FPDF_CreateNewDocument();
  EXPECT_TRUE(output_doc);
  EXPECT_TRUE(FPDF_ImportPages(output_doc, document(), "1", 0));
  EXPECT_TRUE(FPDF_SaveAsCopy(output_doc, this, 0));
  FPDF_CloseDocument(output_doc);

  UnloadPage(page);
}

TEST_F(FPDFSaveEmbedderTest, SaveLinearizedDoc) {
  static constexpr int kPageCount = 3;
  std::string original_md5[kPageCount];

  ASSERT_TRUE(OpenDocument("linearized.pdf"));
  ASSERT_EQ(kPageCount, FPDF_GetPageCount(document()));
  for (int i = 0; i < kPageCount; ++i) {
    FPDF_PAGE page = LoadPage(i);
    ASSERT_TRUE(page);
    ScopedFPDFBitmap bitmap = RenderLoadedPage(page);
    EXPECT_EQ(612, FPDFBitmap_GetWidth(bitmap.get()));
    EXPECT_EQ(792, FPDFBitmap_GetHeight(bitmap.get()));
    original_md5[i] = HashBitmap(bitmap.get());
    UnloadPage(page);
  }

  ASSERT_TRUE(FPDF_SaveAsCopy(document(), this, 0));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.6\r\n"));
  EXPECT_THAT(GetString(), testing::HasSubstr("/Root "));
  EXPECT_THAT(GetString(), testing::HasSubstr("/Info "));
  EXPECT_EQ(8219u, GetString().length());

  // Make sure new document renders the same as the old one.
  FPDF_DOCUMENT saved_doc = OpenSavedDocument();
  ASSERT_TRUE(saved_doc);
  ASSERT_EQ(kPageCount, FPDF_GetPageCount(saved_doc));
  for (int i = 0; i < kPageCount; ++i) {
    FPDF_PAGE page = LoadSavedPage(i);
    ASSERT_TRUE(page);
    ScopedFPDFBitmap bitmap = RenderSavedPage(page);
    EXPECT_EQ(612, FPDFBitmap_GetWidth(bitmap.get()));
    EXPECT_EQ(792, FPDFBitmap_GetHeight(bitmap.get()));
    EXPECT_EQ(original_md5[i], HashBitmap(bitmap.get()));
    CloseSavedPage(page);
  }
  CloseSavedDocument();
}

TEST_F(FPDFSaveEmbedderTest, BUG_342) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));
  EXPECT_THAT(GetString(), testing::HasSubstr("0000000000 65535 f\r\n"));
  EXPECT_THAT(GetString(),
              testing::Not(testing::HasSubstr("0000000000 65536 f\r\n")));
}

TEST_F(FPDFSaveEmbedderTest, BUG_905142) {
  EXPECT_TRUE(OpenDocument("bug_905142.pdf"));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));
  EXPECT_THAT(GetString(), testing::HasSubstr("/Length 0"));
}

TEST_F(FPDFSaveEmbedderTest, SimpleXFA) {
  static constexpr int kPageCount = 2;
  std::string original_md5[kPageCount];

  ASSERT_TRUE(OpenDocument("simple_xfa.pdf"));
  ASSERT_EQ(kPageCount, FPDF_GetPageCount(document()));
  for (int i = 0; i < kPageCount; ++i) {
    FPDF_PAGE page = LoadPage(i);
    ASSERT_TRUE(page);
    ScopedFPDFBitmap bitmap = RenderLoadedPage(page);
    EXPECT_EQ(612, FPDFBitmap_GetWidth(bitmap.get()));
    EXPECT_EQ(792, FPDFBitmap_GetHeight(bitmap.get()));
    original_md5[i] = HashBitmap(bitmap.get());
    UnloadPage(page);
  }

  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));
  EXPECT_THAT(GetString(), testing::StartsWith("%PDF-1.7\r\n"));
  EXPECT_THAT(GetString(), testing::HasSubstr("/Root "));
  EXPECT_THAT(GetString(), testing::HasSubstr("/Info "));
  EXPECT_GT(GetString().length(), 80000u);

  // Make sure new document renders the same as the old one.
  FPDF_DOCUMENT saved_doc = OpenSavedDocument();
  ASSERT_TRUE(saved_doc);
  ASSERT_EQ(kPageCount, FPDF_GetPageCount(saved_doc));
  for (int i = 0; i < kPageCount; ++i) {
    FPDF_PAGE page = LoadSavedPage(i);
    ASSERT_TRUE(page);
    ScopedFPDFBitmap bitmap = RenderSavedPage(page);
    EXPECT_EQ(612, FPDFBitmap_GetWidth(bitmap.get()));
    EXPECT_EQ(792, FPDFBitmap_GetHeight(bitmap.get()));
    // TODO(thestig): Figure out why this fails.
    // EXPECT_EQ(original_md5[i], HashBitmap(bitmap.get()));
    CloseSavedPage(page);
  }
  CloseSavedDocument();
}
