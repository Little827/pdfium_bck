// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_thumbnail.h"
#include "public/fpdfview.h"
#include "testing/embedder_test.h"
#include "testing/utils/hash.h"

class FPDFThumbnailEmbedderTest : public EmbedderTest {};

TEST_F(FPDFThumbnailEmbedderTest, GetDecodedThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    uint8_t buf[8000];
    const char kHashedDecodedData[] = "033864db5248bf30bc3a0c4a9f61535e";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buf, 7524));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    uint8_t buf[8000];
    const char kHashedDecodedData[] = "0f5883a7b9316a2bd6b256bab5590853";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buf, 7524));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    uint8_t buf[8000];
    const char kHashedDecodedData[] = "100a1b436bdb6bf814ecb44b3a8a4f3b";

    EXPECT_EQ(7524u,
              FPDFPage_GetDecodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedDecodedData, GenerateMD5Base16(buf, 7524));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetDecodedThumbnailDataFromPageWithNoThumbnails) {
  // Open a file without thumbnails
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  uint8_t buf[10];

  EXPECT_EQ(0u,
            FPDFPage_GetDecodedThumbnailDataFromPage(page, buf, sizeof(buf)));

  UnloadPage(page);
}

TEST_F(FPDFThumbnailEmbedderTest, GetEncodedThumbnailDataFromPage) {
  // Open a file with thumbnails
  ASSERT_TRUE(OpenDocument("simple_thumbnail.pdf"));

  {
    FPDF_PAGE page = LoadPage(0);
    ASSERT_TRUE(page);

    uint8_t buf[1000];
    const char kHashedEncodedData[] = "6fbea9faf93f34840f4c51460d9d3568";

    EXPECT_EQ(987u,
              FPDFPage_GetEncodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedEncodedData, GenerateMD5Base16(buf, 987));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(1);
    ASSERT_TRUE(page);

    uint8_t buf[1300];
    const char kHashedEncodedData[] = "e7c5732b4b97cf4009d4d2ad8cebd800";

    EXPECT_EQ(1218u,
              FPDFPage_GetEncodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedEncodedData, GenerateMD5Base16(buf, 1218));

    UnloadPage(page);
  }

  {
    FPDF_PAGE page = LoadPage(2);
    ASSERT_TRUE(page);

    uint8_t buf[1300];
    const char kHashedEncodedData[] = "622cf5ab7228533d172a634cecbc3282";

    EXPECT_EQ(1275u,
              FPDFPage_GetEncodedThumbnailDataFromPage(page, buf, sizeof(buf)));
    EXPECT_EQ(kHashedEncodedData, GenerateMD5Base16(buf, 1275));

    UnloadPage(page);
  }
}

TEST_F(FPDFThumbnailEmbedderTest,
       GetEncodedThumbnailDataFromPageWithNoThumbnails) {
  // Open a file without thumbnails
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));

  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);

  uint8_t buf[10];

  EXPECT_EQ(0u,
            FPDFPage_GetEncodedThumbnailDataFromPage(page, buf, sizeof(buf)));

  UnloadPage(page);
}
