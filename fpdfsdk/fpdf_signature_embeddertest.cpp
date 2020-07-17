// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_signature.h"
#include "testing/embedder_test.h"

class FPDFSignatureEmbedderTest : public EmbedderTest {};

TEST_F(FPDFSignatureEmbedderTest, GetSignatureCount) {
  ASSERT_TRUE(OpenDocument("two_signatures.pdf"));
  EXPECT_EQ(2, FPDF_GetSignatureCount(document()));
}

TEST_F(FPDFSignatureEmbedderTest, GetSignatureCountZero) {
  ASSERT_TRUE(OpenDocument("hello_world.pdf"));
  EXPECT_EQ(0, FPDF_GetSignatureCount(document()));

  // Provide no document.
  EXPECT_EQ(-1, FPDF_GetSignatureCount(nullptr));
}

TEST_F(FPDFSignatureEmbedderTest, GetSignatureObject) {
  ASSERT_TRUE(OpenDocument("two_signatures.pdf"));
  // Different, non-null signature objects are returned.
  FPDF_SIGNATURE signature1 = FPDF_GetSignatureObject(document(), 0);
  EXPECT_NE(nullptr, signature1);
  FPDF_SIGNATURE signature2 = FPDF_GetSignatureObject(document(), 1);
  EXPECT_NE(nullptr, signature2);
  EXPECT_NE(signature1, signature2);

  // Out of bounds.
  EXPECT_EQ(nullptr, FPDF_GetSignatureObject(document(), -1));
  EXPECT_EQ(nullptr, FPDF_GetSignatureObject(document(), 2));

  // Provide no document.
  EXPECT_EQ(nullptr, FPDF_GetSignatureObject(nullptr, 0));
}

TEST_F(FPDFSignatureEmbedderTest, GetContents) {
  ASSERT_TRUE(OpenDocument("two_signatures.pdf"));
  FPDF_SIGNATURE signature = FPDF_GetSignatureObject(document(), 0);
  EXPECT_NE(nullptr, signature);

  // FPDFSignatureObj_GetContents() positive testing.
  unsigned long size = FPDFSignatureObj_GetContents(signature, nullptr, 0);
  const uint8_t kExpectedContents[] = {0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48,
                                       0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, 0xA0,
                                       0x80, 0x30, 0x80, 0x02, 0x01, 0x01};
  ASSERT_EQ(sizeof(kExpectedContents), size);
  std::vector<char> contents(size);
  ASSERT_EQ(size,
            FPDFSignatureObj_GetContents(signature, contents.data(), size));
  ASSERT_EQ(0, memcmp(kExpectedContents, contents.data(), size));

  // FPDFSignatureObj_GetContents() negative testing.
  ASSERT_EQ(0U, FPDFSignatureObj_GetContents(nullptr, nullptr, 0));

  contents.resize(2);
  contents[0] = 'x';
  contents[1] = '\0';
  size =
      FPDFSignatureObj_GetContents(signature, contents.data(), contents.size());
  ASSERT_EQ(sizeof(kExpectedContents), size);
  EXPECT_EQ('x', contents[0]);
  EXPECT_EQ('\0', contents[1]);
}
