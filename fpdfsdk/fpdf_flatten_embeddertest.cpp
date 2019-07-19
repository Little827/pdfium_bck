// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_annot.h"
#include "public/fpdf_flatten.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

class FPDFFlattenEmbedderTest : public EmbedderTest {};

}  // namespace

TEST_F(FPDFFlattenEmbedderTest, FlatNothing) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_NOTHINGTODO, FPDFPage_Flatten(page, FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, FlatNormal) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, FlatPrint) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_PRINT));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, BUG_890322) {
  static const char md5_hash[] = "6c674642154408e877d88c6c082d67e9";
  EXPECT_TRUE(OpenDocument("bug_890322.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 200, 200, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  VerifySavedDocument(200, 200, md5_hash);
}

TEST_F(FPDFFlattenEmbedderTest, BUG_896366) {
  static const char md5_hash[] = "f71ab085c52c8445ae785eca3ec858b1";
  EXPECT_TRUE(OpenDocument("bug_896366.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 612, 792, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_Flatten(page, FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  VerifySavedDocument(612, 792, md5_hash);
}

TEST_F(FPDFFlattenEmbedderTest, BUG_954307) {
#if defined(OS_MACOSX)
  static const char md5_hash[] = "97d8c820c2c2d93f6e8025dffa5c42eb";
  static const char md5_hash_flat[] = "e2511495540d98fece6d8e4f80c87437";
#elif defined(OS_WIN)
  static const char md5_hash[] = "9b2dd769711b54c47fd54c4b292ad0e8";
  static const char md5_hash_flat[] = "f724caf2b832880a85d46445effb288e";
#else
  static const char md5_hash[] = "072d074fc6fec24fbd5742a6dc747ff3";
  static const char md5_hash_flat[] = "c64a2a7f3add23b3d7ab94e7064ea20d";
#endif
  EXPECT_TRUE(OpenDocument("combobox_form.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_NE(FPDFPage_GetAnnotCount(page), 0);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 300, 600, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_Flatten_No_Controls(page, form_handle(), FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  EXPECT_TRUE(OpenSavedDocument());
  FPDF_PAGE saved_page = LoadSavedPage(0);
  EXPECT_TRUE(saved_page);
  EXPECT_EQ(FPDFPage_GetAnnotCount(saved_page), 0);

  ScopedFPDFBitmap saved_bitmap =
      RenderSavedPageWithFlags(saved_page, FPDF_ANNOT);
  CompareBitmap(saved_bitmap.get(), 300, 600, md5_hash_flat);

  CloseSavedPage(saved_page);
  CloseSavedDocument();
}
