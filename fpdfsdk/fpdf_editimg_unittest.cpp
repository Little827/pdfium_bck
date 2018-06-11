// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_edit.h"

#include "core/fpdfapi/cpdf_modulemgr.h"
#include "testing/gtest/include/gtest/gtest.h"

class PDFEditTest : public testing::Test {
  void SetUp() override { CPDF_ModuleMgr::Get()->Init(); }

  void TearDown() override { CPDF_ModuleMgr::Destroy(); }
};

TEST_F(PDFEditTest, InsertObjectWithInvalidPage) {
  FPDF_DOCUMENT doc = FPDF_CreateNewDocument();
  FPDF_PAGE page = FPDFPage_New(doc, 0, 100, 100);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  FPDFPage_InsertObject(nullptr, nullptr);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  FPDFPage_InsertObject(page, nullptr);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  FPDF_PAGEOBJECT page_image = FPDFPageObj_NewImageObj(doc);
  FPDFPage_InsertObject(nullptr, page_image);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  FPDF_ClosePage(page);
  FPDF_CloseDocument(doc);
}

TEST_F(PDFEditTest, NewImageObj) {
  FPDF_DOCUMENT doc = FPDF_CreateNewDocument();
  FPDF_PAGE page = FPDFPage_New(doc, 0, 100, 100);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  FPDF_PAGEOBJECT page_image = FPDFPageObj_NewImageObj(doc);
  FPDFPage_InsertObject(page, page_image);
  EXPECT_EQ(1, FPDFPage_CountObjects(page));
  EXPECT_TRUE(FPDFPage_GenerateContent(page));

  FPDF_ClosePage(page);
  FPDF_CloseDocument(doc);
}

TEST_F(PDFEditTest, NewBitmapImageObj) {
  FPDF_DOCUMENT doc = FPDF_CreateNewDocument();
  FPDF_PAGE page = FPDFPage_New(doc, 0, 100, 100);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));
  FPDF_BITMAP bitmap = FPDFBitmap_Create(100, 100, false);

  FPDF_PAGEOBJECT page_image = FPDFPageObj_NewBitmapImageObj(doc, bitmap);
  {
    FPDF_BITMAP created_bitmap = FPDFImageObj_GetBitmap(page_image);
    EXPECT_EQ(100, FPDFBitmap_GetWidth(created_bitmap));
    EXPECT_EQ(100, FPDFBitmap_GetHeight(created_bitmap));
    FPDFBitmap_Destroy(created_bitmap);
  }
  FPDFPage_InsertObject(page, page_image);
  EXPECT_EQ(1, FPDFPage_CountObjects(page));
  EXPECT_TRUE(FPDFPage_GenerateContent(page));

  FPDFBitmap_Destroy(bitmap);
  FPDF_ClosePage(page);
  FPDF_CloseDocument(doc);
}

TEST_F(PDFEditTest, NewJpegImageObjInline) {
  FPDF_DOCUMENT doc = FPDF_CreateNewDocument();
  FPDF_PAGE page = FPDFPage_New(doc, 0, 100, 100);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  static const char kJpegFile[] =
      "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48"
      "\x00\x00\xFF\xDB\x00\x43\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
      "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
      "\xC2\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00\xFF\xC4\x00\x14\x10\x01"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA"
      "\x00\x08\x01\x01\x00\x01\x3F\x10";
  static const uint32_t kJpegSize = sizeof(kJpegFile) - 1;
  FPDF_PAGEOBJECT page_image =
      FPDFPageObj_NewJpegImageObjInline(doc, kJpegFile, kJpegSize);
  {
    char buffer[kJpegSize];
    ASSERT_EQ(kJpegSize,
              FPDFImageObj_GetImageDataRaw(page_image, buffer, kJpegSize));
    EXPECT_FALSE(memcmp(kJpegFile, buffer, kJpegSize));
  }

  FPDFPage_InsertObject(page, page_image);
  EXPECT_EQ(1, FPDFPage_CountObjects(page));
  EXPECT_TRUE(FPDFPage_GenerateContent(page));

  FPDF_ClosePage(page);
  FPDF_CloseDocument(doc);
}

TEST_F(PDFEditTest, NewImageObjGenerateContent) {
  FPDF_DOCUMENT doc = FPDF_CreateNewDocument();
  FPDF_PAGE page = FPDFPage_New(doc, 0, 100, 100);
  EXPECT_EQ(0, FPDFPage_CountObjects(page));

  constexpr int kBitmapSize = 50;
  FPDF_BITMAP bitmap = FPDFBitmap_Create(kBitmapSize, kBitmapSize, 0);
  FPDFBitmap_FillRect(bitmap, 0, 0, kBitmapSize, kBitmapSize, 0x00000000);
  EXPECT_EQ(kBitmapSize, FPDFBitmap_GetWidth(bitmap));
  EXPECT_EQ(kBitmapSize, FPDFBitmap_GetHeight(bitmap));

  FPDF_PAGEOBJECT page_image = FPDFPageObj_NewImageObj(doc);
  ASSERT_TRUE(FPDFImageObj_SetBitmap(&page, 0, page_image, bitmap));
  ASSERT_TRUE(
      FPDFImageObj_SetMatrix(page_image, kBitmapSize, 0, 0, kBitmapSize, 0, 0));
  FPDFPage_InsertObject(page, page_image);
  EXPECT_EQ(1, FPDFPage_CountObjects(page));
  EXPECT_TRUE(FPDFPage_GenerateContent(page));

  FPDFBitmap_Destroy(bitmap);
  FPDF_ClosePage(page);
  FPDF_CloseDocument(doc);
}
