// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_thumbnail.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/utils/hash.h"

class FPDFThumbnailEmbedderTest : public EmbedderTest {};

TEST_F(FPDFThumbnailEmbedderTest, GetThumbnailStreamSize) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    EXPECT_EQ(987u, FPDFPage_GetThumbnailStreamSize(page));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    EXPECT_EQ(1218u, FPDFPage_GetThumbnailStreamSize(page));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    EXPECT_EQ(1275u, FPDFPage_GetThumbnailStreamSize(page));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest, GetDecodedThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    const unsigned long kBufLen = 7524u;
    uint8_t buffer[kBufLen];
    const char kHashedDecodedData[] = "033864db5248bf30bc3a0c4a9f61535e";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buffer, 7524));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    const unsigned long kBufLen = 7524u;
    uint8_t buffer[kBufLen];
    const char kHashedDecodedData[] = "0f5883a7b9316a2bd6b256bab5590853";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buffer, 7524));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    unsigned long kBufLen = 7524u;
    uint8_t buffer[kBufLen];
    const char kHashedDecodedData[] = "100a1b436bdb6bf814ecb44b3a8a4f3b";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buffer, 7524));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest, GetRawThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    unsigned long kBufLen = 987u;
    uint8_t buffer[kBufLen];
    const char kHashedRawData[] = "6fbea9faf93f34840f4c51460d9d3568";

    EXPECT_EQ(987u,
              FPDFPage_GetRawThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedRawData, GenerateMD5Base16(buffer, 987));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    unsigned long kBufLen = 1218u;
    uint8_t buffer[kBufLen];
    const char kHashedRawData[] = "e7c5732b4b97cf4009d4d2ad8cebd800";

    EXPECT_EQ(1218u,
              FPDFPage_GetRawThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedRawData, GenerateMD5Base16(buffer, 1218));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    unsigned long kBufLen = 1275u;
    uint8_t buffer[kBufLen];
    const char kHashedRawData[] = "622cf5ab7228533d172a634cecbc3282";

    EXPECT_EQ(1275u,
              FPDFPage_GetRawThumbnailDataFromPage(page, buffer, kBufLen));
    EXPECT_EQ(kHashedRawData, GenerateMD5Base16(buffer, 1275));

    UnloadPage(page);
  }
}
