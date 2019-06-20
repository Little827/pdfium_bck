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
    const char kHashedDecodedData[] = "899acfa4430e9df120d7a663c0b75fc2";
    const unsigned long kExpectedSize = 7738u;

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetDecodedThumbnailDataFromPage(page, nullptr, 0);
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
        FPDFPage_GetDecodedThumbnailDataFromPage(page, nullptr, 0);
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
      FPDFPage_GetDecodedThumbnailDataFromPage(page, nullptr, 0);
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

  EXPECT_EQ(0u, FPDFPage_GetDecodedThumbnailDataFromPage(page, nullptr, 0));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPageWithFilters) {
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    const char kHashedRawData[] = "744739c1154bed35f7cfe7a7461c6ab3";
    const unsigned long kExpectedSize = 749u;

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0);
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
        FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0);
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
      FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0);
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

  EXPECT_EQ(0u, FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetThumbnailAsBitmapFromPage) {
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));

    EXPECT_EQ(50, FPDFBitmap_GetWidth(thumb_bitmap.get()));
    EXPECT_EQ(50, FPDFBitmap_GetHeight(thumb_bitmap.get()));
    EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap.get()));
    CompareBitmap(thumb_bitmap.get(), 50, 50,
                  "a053404a2fc018a219105d3a7c1b9e76");

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
}

TEST_F(FPDFThumbnailEmbedderTest, GetThumbnailDoesNotAlterPage) {
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  const char kHashedRawData[] = "744739c1154bed35f7cfe7a7461c6ab3";
  const unsigned long kExpectedRawSize = 749u;

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  // Get the raw data
  unsigned long raw_size =
      FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0);
  ASSERT_EQ(kExpectedRawSize, raw_size);
  std::vector<uint8_t> raw_thumb_buf(raw_size);

  EXPECT_EQ(kExpectedRawSize, FPDFPage_GetRawThumbnailDataFromPage(
                                  page, raw_thumb_buf.data(), raw_size));
  EXPECT_EQ(kHashedRawData,
            GenerateMD5Base16(raw_thumb_buf.data(), kExpectedRawSize));

  // Get the thumbnail
  ScopedFPDFBitmap thumb_bitmap(FPDFPage_GetThumbnailAsBitmapFromPage(page));

  EXPECT_EQ(50, FPDFBitmap_GetWidth(thumb_bitmap.get()));
  EXPECT_EQ(50, FPDFBitmap_GetHeight(thumb_bitmap.get()));
  EXPECT_EQ(FPDFBitmap_BGR, FPDFBitmap_GetFormat(thumb_bitmap.get()));
  CompareBitmap(thumb_bitmap.get(), 50, 50, "a053404a2fc018a219105d3a7c1b9e76");

  // Get the raw data again
  unsigned long new_raw_size =
      FPDFPage_GetRawThumbnailDataFromPage(page, nullptr, 0);
  ASSERT_EQ(kExpectedRawSize, new_raw_size);
  std::vector<uint8_t> new_raw_thumb_buf(new_raw_size);

  EXPECT_EQ(kExpectedRawSize,
            FPDFPage_GetRawThumbnailDataFromPage(page, new_raw_thumb_buf.data(),
                                                 new_raw_size));
  EXPECT_EQ(kHashedRawData,
            GenerateMD5Base16(new_raw_thumb_buf.data(), kExpectedRawSize));

  UnloadPage(page);
}
