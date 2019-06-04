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
    const char kHashedDecodedData[] = "033864db5248bf30bc3a0c4a9f61535e";

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetDecodedThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(7524u, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(7524u, FPDFPage_GetDecodedThumbnailDataFromPage(
                         page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(thumb_buf.data(), 7524));

    UnloadPage(page);
  }

  {
    const char kHashedDecodedData[] = "0f5883a7b9316a2bd6b256bab5590853";

    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetDecodedThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(7524u, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(7524u, FPDFPage_GetDecodedThumbnailDataFromPage(
                         page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(thumb_buf.data(), 7524));

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
    const char kHashedRawData[] = "6fbea9faf93f34840f4c51460d9d3568";

    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetRawThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(987u, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(987u, FPDFPage_GetRawThumbnailDataFromPage(page, thumb_buf.data(),
                                                         length_bytes));
    EXPECT_EQ(kHashedRawData, GenerateMD5Base16(thumb_buf.data(), 987));

    UnloadPage(page);
  }

  {
    const char kHashedRawData[] = "e7c5732b4b97cf4009d4d2ad8cebd800";

    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    unsigned long length_bytes =
        FPDFPage_GetRawThumbnailDataFromPage(page, NULL, 0);
    ASSERT_EQ(1218u, length_bytes);
    std::vector<uint8_t> thumb_buf(length_bytes);

    EXPECT_EQ(1218u, FPDFPage_GetRawThumbnailDataFromPage(
                         page, thumb_buf.data(), length_bytes));
    EXPECT_EQ(kHashedRawData, GenerateMD5Base16(thumb_buf.data(), 1218));

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
