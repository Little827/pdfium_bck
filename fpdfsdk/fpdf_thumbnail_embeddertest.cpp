// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "public/fpdf_thumbnail.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/utils/hash.h"

class FPDFThumbnailEmbedderTest : public EmbedderTest {};

TEST_F(FPDFThumbnailEmbedderTest, GetDecodedThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    const char kHashedDecodedData[] = "6518acbc5086e0a49032e84f2f706955";
    const unsigned long kExpectedSize = 40586u;

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetDecodedThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(kExpectedSize, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(kExpectedSize, FPDFPage_GetDecodedThumbnailDataFromPage(
                                 page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedDecodedData,
              GenerateMD5Base16(thumb_buf.data(), kExpectedSize));

    UnloadPage(page);
  }

  {
    const char kHashedDecodedData[] = "ce43dbccfc356f478f0d7533a5bdf2c0";
    const unsigned long kExpectedSize = 7738u;

    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetDecodedThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(kExpectedSize, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(kExpectedSize, FPDFPage_GetDecodedThumbnailDataFromPage(
                                 page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedDecodedData,
              GenerateMD5Base16(thumb_buf.data(), kExpectedSize));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetDecodedThumbnailDataFromPageWithNoThumbnails) {
  // Open a file without thumbnails
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  // Assign arbitrary size buffer since it shouldn't be filled anyways
  uint8_t buf[10];

  EXPECT_EQ(0u,
            FPDFPage_GetDecodedThumbnailDataFromPage(page, buf, sizeof(buf)));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    const char kHashedRawData[] = "f8de1df8682cb7127c325da170e0c513";
    const unsigned long kExpectedSize = 61509u;

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetRawThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(kExpectedSize, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(kExpectedSize, FPDFPage_GetRawThumbnailDataFromPage(
                                 page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedRawData,
              GenerateMD5Base16(thumb_buf.data(), kExpectedSize));

    UnloadPage(page);
  }

  {
    const char kHashedRawData[] = "2d82bbf08b917192d56f048e7d2e9b24";
    const unsigned long kExpectedSize = 2558u;

    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetRawThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(kExpectedSize, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(kExpectedSize, FPDFPage_GetRawThumbnailDataFromPage(
                                 page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedRawData,
              GenerateMD5Base16(thumb_buf.data(), kExpectedSize));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPageWithNoThumbnails) {
  // Open a file without thumbnails
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  // Assign arbitrary size buffer since it shouldn't be filled anyways
  uint8_t buf[10];

  EXPECT_EQ(0u, FPDFPage_GetRawThumbnailDataFromPage(page, buf, sizeof(buf)));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetThumbnailAsBitmapFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    FPDF_BITMAP thumb_bitmap = FPDFPage_GetThumbnailAsBitmapFromPage(page);

    EXPECT_EQ(100, FPDFBitmap_GetWidth(thumb_bitmap));
    EXPECT_EQ(133, FPDFBitmap_GetHeight(thumb_bitmap));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap));
    CompareBitmap(thumb_bitmap, 100, 133, "ca4eee7ea0bb4d50b92a93accc2013ab");

    FPDFBitmap_Destroy(thumb_bitmap);
    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    FPDF_BITMAP thumb_bitmap = FPDFPage_GetThumbnailAsBitmapFromPage(page);

    EXPECT_EQ(50, FPDFBitmap_GetWidth(thumb_bitmap));
    EXPECT_EQ(50, FPDFBitmap_GetHeight(thumb_bitmap));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap));
    CompareBitmap(thumb_bitmap, 50, 50, "341a10cfce263f06ecdd010aef605851");

    FPDFBitmap_Destroy(thumb_bitmap);
    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetThumbnailAsBitmapFromPageWithoutThumbnail) {
  // Open a file without thumbnails
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  FPDF_BITMAP thumb_bitmap = FPDFPage_GetThumbnailAsBitmapFromPage(page);
  ASSERT_EQ(nullptr, thumb_bitmap);

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetThumbnailAsBitmapFromPageWithMalformedThumbnail) {
  ASSERT_TRUE(OpenDocument("empty_thumbnail.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  FPDF_BITMAP thumb_bitmap = FPDFPage_GetThumbnailAsBitmapFromPage(page);
  ASSERT_EQ(nullptr, thumb_bitmap);

  UnloadPage(page);
}
