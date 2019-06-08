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
    const char kHashedDecodedData[] = "169e16db9da120728f16c0f4336a6081";
    const unsigned long kExpectedSize = 14863u;

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
    const char kHashedDecodedData[] = "0f64074b7c68875a3c82599bceded584";
    const unsigned long kExpectedSize = 1380u;

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
    const char kHashedRawData[] = "724ba6bb4fc861597916d6a8458069a8";
    const unsigned long kExpectedSize = 27383u;

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
    const char kHashedRawData[] = "0c1404ebea2c2e608236290f9e52bc9c";
    const unsigned long kExpectedSize = 2829u;

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
    CompareBitmap(thumb_bitmap, 100, 133, "c29a44e16128d524ad9a48f36fa9ab8b");

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
    CompareBitmap(thumb_bitmap, 50, 50, "c9235a9f8487eea0975af854c96738a8");

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
