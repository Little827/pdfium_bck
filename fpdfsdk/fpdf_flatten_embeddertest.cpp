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

TEST_F(FPDFFlattenEmbedderTest, FlatNothingNoControls) {
  EXPECT_TRUE(OpenDocument("hello_world.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_NOTHINGTODO, FPDFPage_FlattenNoControls(
                                     page, form_handle(), FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, FlatNormalNoControls) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS, FPDFPage_FlattenNoControls(page, form_handle(),
                                                        FLAT_NORMALDISPLAY));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, FlatPrintNoControls) {
  EXPECT_TRUE(OpenDocument("annotiter.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
  UnloadPage(page);
}

TEST_F(FPDFFlattenEmbedderTest, BUG_890322NoControls) {
  static const char md5_hash[] = "6c674642154408e877d88c6c082d67e9";
  EXPECT_TRUE(OpenDocument("bug_890322.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 200, 200, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  VerifySavedDocument(200, 200, md5_hash);
}

TEST_F(FPDFFlattenEmbedderTest, BUG_896366NoControls) {
  static const char md5_hash[] = "f71ab085c52c8445ae785eca3ec858b1";
  EXPECT_TRUE(OpenDocument("bug_896366.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 612, 792, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  VerifySavedDocument(612, 792, md5_hash);
}

TEST_F(FPDFFlattenEmbedderTest, FlatComboBox) {
#if defined(OS_MACOSX)
  static const char md5_hash[] = "1f60be99ea9797b56f0aeb1197bd3a20";
  static const char md5_hash_flat[] = "5b90b61d6f436eac61a6f59c554a58d1";
#elif defined(OS_WIN)
  static const char md5_hash[] = "73f65f7c0e674a96ac144035bd35bd42";
  static const char md5_hash_flat[] = "b017fdf0ce934f02b9943499c6e87b07";
#else
  static const char md5_hash[] = "6446192436cb115d611bcd94fc1a0cb5";
  static const char md5_hash_flat[] = "86a051673beeb92e9f672b27ecb109e0";
#endif
  EXPECT_TRUE(OpenDocument("combobox_form.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FPDFPage_GetAnnotCount(page), 4);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 300, 600, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
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

TEST_F(FPDFFlattenEmbedderTest, FlatListBox) {
#if defined(OS_MACOSX)
  static const char md5_hash[] = "e2757c52d9881e80c71c9c0a00654b1a";
  static const char md5_hash_flat[] = "f31d3856fdfd821a9590fc3c6af51de3";
#elif defined(OS_WIN)
  static const char md5_hash[] = "c02c273c0bce76433f8894808923e18b";
  static const char md5_hash_flat[] = "b18450e3c625d4212664f1d97661a9f1";
#else
  static const char md5_hash[] = "6b85c286ee21e49bf64872aa1bab23b9";
  static const char md5_hash_flat[] = "af90f212a1f3d4192a4782050c4d13ab";
#endif
  EXPECT_TRUE(OpenDocument("listbox_form.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FPDFPage_GetAnnotCount(page), 3);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 300, 600, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
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

TEST_F(FPDFFlattenEmbedderTest, FlatClickForm) {
#if defined(OS_MACOSX)
  static const char md5_hash[] = "680c39dfe9b09b1654c3e431e5015d21";
  static const char md5_hash_flat[] = "ec6eb547068866386a686af38b2c96c4";
#else
  static const char md5_hash[] = "0307325d8c96ec009dfd53e708288b7e";
  static const char md5_hash_flat[] = "7170dbfa068226eb1ccfbe0d75e92c5d";
#endif
  EXPECT_TRUE(OpenDocument("click_form.pdf"));
  FPDF_PAGE page = LoadPage(0);
  EXPECT_TRUE(page);
  EXPECT_EQ(FPDFPage_GetAnnotCount(page), 8);

  ScopedFPDFBitmap bitmap = RenderLoadedPageWithFlags(page, FPDF_ANNOT);
  CompareBitmap(bitmap.get(), 300, 300, md5_hash);

  EXPECT_EQ(FLATTEN_SUCCESS,
            FPDFPage_FlattenNoControls(page, form_handle(), FLAT_PRINT));
  EXPECT_TRUE(FPDF_SaveAsCopy(document(), this, 0));

  UnloadPage(page);

  EXPECT_TRUE(OpenSavedDocument());
  FPDF_PAGE saved_page = LoadSavedPage(0);
  EXPECT_TRUE(saved_page);
  EXPECT_EQ(FPDFPage_GetAnnotCount(saved_page), 0);

  ScopedFPDFBitmap saved_bitmap =
      RenderSavedPageWithFlags(saved_page, FPDF_ANNOT);
  CompareBitmap(saved_bitmap.get(), 300, 300, md5_hash_flat);

  CloseSavedPage(saved_page);
  CloseSavedDocument();
}
