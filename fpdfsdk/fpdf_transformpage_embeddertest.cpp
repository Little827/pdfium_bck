// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_transformpage.h"
#include "testing/embedder_test.h"

class FPDFTransformEmbedderTest : public EmbedderTest {};

TEST_F(FPDFTransformEmbedderTest, GetBoundingBoxes) {
  ASSERT_TRUE(OpenDocument("cropped_text.pdf"));
  ASSERT_EQ(4, FPDF_GetPageCount(document()));

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    FS_RECTF mediabox;
    EXPECT_TRUE(FPDFPage_GetMediaBox(page, &mediabox.left, &mediabox.bottom,
                                     &mediabox.right, &mediabox.top));
    EXPECT_EQ(-50, mediabox.left);
    EXPECT_EQ(-50, mediabox.bottom);
    EXPECT_EQ(200, mediabox.right);
    EXPECT_EQ(200, mediabox.top);

    FS_RECTF cropbox;
    EXPECT_TRUE(FPDFPage_GetCropBox(page, &cropbox.left, &cropbox.bottom,
                                    &cropbox.right, &cropbox.top));
    EXPECT_EQ(50, cropbox.left);
    EXPECT_EQ(50, cropbox.bottom);
    EXPECT_EQ(150, cropbox.right);
    EXPECT_EQ(150, cropbox.top);

    FS_RECTF bleedbox;
    EXPECT_TRUE(FPDFPage_GetBleedBox(page, &bleedbox.left, &bleedbox.bottom,
                                     &bleedbox.right, &bleedbox.top));
    EXPECT_EQ(0, bleedbox.left);
    EXPECT_EQ(10, bleedbox.bottom);
    EXPECT_EQ(150, bleedbox.right);
    EXPECT_EQ(145, bleedbox.top);

    FS_RECTF trimbox;
    EXPECT_TRUE(FPDFPage_GetTrimBox(page, &trimbox.left, &trimbox.bottom,
                                    &trimbox.right, &trimbox.top));
    EXPECT_EQ(25, trimbox.left);
    EXPECT_EQ(30, trimbox.bottom);
    EXPECT_EQ(140, trimbox.right);
    EXPECT_EQ(145, trimbox.top);

    FS_RECTF artbox;
    EXPECT_TRUE(FPDFPage_GetArtBox(page, &artbox.left, &artbox.bottom,
                                   &artbox.right, &artbox.top));
    EXPECT_EQ(50, artbox.left);
    EXPECT_EQ(60, artbox.bottom);
    EXPECT_EQ(135, artbox.right);
    EXPECT_EQ(140, artbox.top);

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(3);
    ASSERT_TRUE(page);

    FS_RECTF mediabox;
    EXPECT_TRUE(FPDFPage_GetMediaBox(page, &mediabox.left, &mediabox.bottom,
                                     &mediabox.right, &mediabox.top));
    EXPECT_EQ(0, mediabox.left);
    EXPECT_EQ(0, mediabox.bottom);
    EXPECT_EQ(200, mediabox.right);
    EXPECT_EQ(200, mediabox.top);

    FS_RECTF cropbox;
    EXPECT_TRUE(FPDFPage_GetCropBox(page, &cropbox.left, &cropbox.bottom,
                                    &cropbox.right, &cropbox.top));
    EXPECT_EQ(150, cropbox.left);
    EXPECT_EQ(150, cropbox.bottom);
    EXPECT_EQ(60, cropbox.right);
    EXPECT_EQ(60, cropbox.top);

    EXPECT_FALSE(FPDFPage_GetCropBox(page, nullptr, &cropbox.bottom,
                                     &cropbox.right, &cropbox.top));
    EXPECT_FALSE(FPDFPage_GetCropBox(page, &cropbox.left, nullptr,
                                     &cropbox.right, &cropbox.top));
    EXPECT_FALSE(FPDFPage_GetCropBox(page, &cropbox.left, &cropbox.bottom,
                                     nullptr, &cropbox.top));
    EXPECT_FALSE(FPDFPage_GetCropBox(page, &cropbox.left, &cropbox.bottom,
                                     &cropbox.right, nullptr));
    EXPECT_FALSE(FPDFPage_GetCropBox(page, nullptr, nullptr, nullptr, nullptr));

    FS_RECTF bleedbox;
    EXPECT_TRUE(FPDFPage_GetBleedBox(page, &bleedbox.left, &bleedbox.bottom,
                                     &bleedbox.right, &bleedbox.top));
    EXPECT_EQ(160, bleedbox.left);
    EXPECT_EQ(165, bleedbox.bottom);
    EXPECT_EQ(0, bleedbox.right);
    EXPECT_EQ(10, bleedbox.top);

    FS_RECTF trimbox;
    EXPECT_TRUE(FPDFPage_GetTrimBox(page, &trimbox.left, &trimbox.bottom,
                                    &trimbox.right, &trimbox.top));
    EXPECT_EQ(155, trimbox.left);
    EXPECT_EQ(165, trimbox.bottom);
    EXPECT_EQ(25, trimbox.right);
    EXPECT_EQ(30, trimbox.top);

    FS_RECTF artbox;
    EXPECT_TRUE(FPDFPage_GetArtBox(page, &artbox.left, &artbox.bottom,
                                   &artbox.right, &artbox.top));
    EXPECT_EQ(140, artbox.left);
    EXPECT_EQ(145, artbox.bottom);
    EXPECT_EQ(65, artbox.right);
    EXPECT_EQ(70, artbox.top);

    UnloadPage(page);
  }
}

TEST_F(FPDFTransformEmbedderTest, NoCropBox) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));
  ASSERT_EQ(1, FPDF_GetPageCount(document()));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  float left = -1.0f;
  float bottom = -2.0f;
  float right = 3.0f;
  float top = 0.0f;
  EXPECT_FALSE(FPDFPage_GetCropBox(page, &left, &bottom, &right, &top));
  EXPECT_EQ(-1.0f, left);
  EXPECT_EQ(-2.0f, bottom);
  EXPECT_EQ(3.0f, right);
  EXPECT_EQ(0.0f, top);

  UnloadPage(page);
}

TEST_F(FPDFTransformEmbedderTest, NoBleedBox) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));
  ASSERT_EQ(1, FPDF_GetPageCount(document()));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  float left = -1.0f;
  float bottom = -1.0f;
  float right = 3.0f;
  float top = 10.0f;
  EXPECT_FALSE(FPDFPage_GetBleedBox(page, &left, &bottom, &right, &top));
  EXPECT_EQ(-1.0f, left);
  EXPECT_EQ(-1.0f, bottom);
  EXPECT_EQ(3.0f, right);
  EXPECT_EQ(10.0f, top);

  UnloadPage(page);
}

TEST_F(FPDFTransformEmbedderTest, NoTrimBox) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));
  ASSERT_EQ(1, FPDF_GetPageCount(document()));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  float left = -11.0f;
  float bottom = -10.0f;
  float right = 3.0f;
  float top = 0.0f;
  EXPECT_FALSE(FPDFPage_GetTrimBox(page, &left, &bottom, &right, &top));
  EXPECT_EQ(-11.0f, left);
  EXPECT_EQ(-10.0f, bottom);
  EXPECT_EQ(3.0f, right);
  EXPECT_EQ(0.0f, top);

  UnloadPage(page);
}

TEST_F(FPDFTransformEmbedderTest, NoArtBox) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));
  ASSERT_EQ(1, FPDF_GetPageCount(document()));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  float left = -1.0f;
  float bottom = -1.0f;
  float right = 3.0f;
  float top = 0.0f;
  EXPECT_FALSE(FPDFPage_GetArtBox(page, &left, &bottom, &right, &top));
  EXPECT_EQ(-1.0f, left);
  EXPECT_EQ(-1.0f, bottom);
  EXPECT_EQ(3.0f, right);
  EXPECT_EQ(0.0f, top);

  UnloadPage(page);
}

TEST_F(FPDFTransformEmbedderTest, ClipPath) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  FPDF_CLIPPATH clip = FPDF_CreateClipPath(10.0f, 10.0f, 90.0f, 90.0f);
  EXPECT_TRUE(clip);

  // NULL arg call is a no-op.
  FPDFPage_InsertClipPath(nullptr, clip);

  // Do actual work.
  FPDFPage_InsertClipPath(page, clip);

  // TODO(tsepez): test how inserting path affects page rendering.

  FPDF_DestroyClipPath(clip);
  UnloadPage(page);
}
