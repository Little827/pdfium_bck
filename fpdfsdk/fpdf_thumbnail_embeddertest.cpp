// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "public/fpdf_thumbnail.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/utils/hash.h"

class FPDFThumbnailEmbedderTest : public EmbedderTest {};

TEST_F(FPDFThumbnailEmbedderTest, GetDecodedThumbnailDataFromPageWithFilters) {
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
       GetDecodedThumbnailDataFromPageWithNoFilters) {
  ASSERT_TRUE(OpenDocument("edge_case_thumbnails.pdf"));

  const char kHashedDecodedData[] = "0c1404ebea2c2e608236290f9e52bc9c";
  const unsigned long kExpectedSize = 2829u;

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

TEST_F(FPDFThumbnailEmbedderTest,
       GetDecodedThumbnailDataFromPageWithNoThumbnails) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  // Assign arbitrary size buffer since it shouldn't be filled anyways
  std::vector<uint8_t> buf(10);

  EXPECT_EQ(0u, FPDFPage_GetDecodedThumbnailDataFromPage(page, buf.data(),
                                                         buf.size()));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetDecodedThumbnailDataFromPageWithWrongFilter) {
  ASSERT_TRUE(OpenDocument("edge_case_thumbnails.pdf"));

  FPDF_PAGE page = LoadPage(2);
  ASSERT_TRUE(page);

  std::vector<uint8_t> buf(10);
  EXPECT_EQ(0u, FPDFPage_GetDecodedThumbnailDataFromPage(page, buf.data(),
                                                         buf.size()));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPageWithFilters) {
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

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPageWithNoFilters) {
  ASSERT_TRUE(OpenDocument("edge_case_thumbnails.pdf"));

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
  EXPECT_EQ(kHashedRawData, GenerateMD5Base16(thumb_buf.data(), kExpectedSize));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPageWithNoThumbnails) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  // Assign arbitrary size buffer since it shouldn't be filled anyways
  std::vector<uint8_t> buf(10);

  EXPECT_EQ(0u,
            FPDFPage_GetRawThumbnailDataFromPage(page, buf.data(), buf.size()));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetThumbnailAsBitmapFromPage) {
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));

    EXPECT_EQ(100, FPDFBitmap_GetWidth(thumb_bitmap.get()));
    EXPECT_EQ(133, FPDFBitmap_GetHeight(thumb_bitmap.get()));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap.get()));
    CompareBitmap(thumb_bitmap.get(), 100, 133,
                  "2c0d9473e12ec470ecef471677664a8f");

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));

    EXPECT_EQ(50, FPDFBitmap_GetWidth(thumb_bitmap.get()));
    EXPECT_EQ(50, FPDFBitmap_GetHeight(thumb_bitmap.get()));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap.get()));
    CompareBitmap(thumb_bitmap.get(), 50, 50,
                  "efb9a7378c38a924d9e09fe87ff0179e");

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetThumbnailAsBitmapFromPageWithoutThumbnail) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));
  ASSERT_EQ(nullptr, thumb_bitmap.get());

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetThumbnailAsBitmapFromPageWithEdgeCaseThumbnails) {
  ASSERT_TRUE(OpenDocument("edge_case_thumbnails.pdf"));

  {
    // Thumbnail has empty stream
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));
    ASSERT_EQ(nullptr, thumb_bitmap.get());

    UnloadPage(page);
  }

  {
    // Thumbnail with no filters
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));

    EXPECT_EQ(50, FPDFBitmap_GetWidth(thumb_bitmap.get()));
    EXPECT_EQ(50, FPDFBitmap_GetHeight(thumb_bitmap.get()));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap.get()));
    CompareBitmap(thumb_bitmap.get(), 50, 50,
                  "b6f6cea9609d3929589fd0992470a0b1");

    UnloadPage(page);
  }

  {
    // Thumbnail has wrong filters
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));
    ASSERT_EQ(nullptr, thumb_bitmap.get());

    UnloadPage(page);
  }
}
