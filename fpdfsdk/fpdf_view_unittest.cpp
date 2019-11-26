// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdfview.h"
#include "testing/gtest/include/gtest/gtest.h"

#ifdef PDF_ENABLE_XFA
TEST(FPDFView, EmptyBstr) {
  FPDF_BSTR bst;
  FPDF_BStr_Init(&bst);
  EXPECT_FALSE(bst.str);
  EXPECT_FALSE(bst.len);
  FPDF_BStr_Clear(&bst);
}

TEST(FPDFView, NormalBstr) {
  FPDF_BSTR bst;
  FPDF_BStr_Init(&bst);
  FPDF_BStr_Set(&bst, "clams", -1);
  EXPECT_STREQ("clams", bst.str);
  EXPECT_EQ(5, bst.len);

  FPDF_BStr_Clear(&bst);
  EXPECT_FALSE(bst.str);
  EXPECT_FALSE(bst.len);
}

TEST(FPDFView, ReassignBstr) {
  FPDF_BSTR bst;
  FPDF_BStr_Init(&bst);
  FPDF_BStr_Set(&bst, "clams", 3);
  EXPECT_STREQ("cla", bst.str);
  EXPECT_EQ(3, bst.len);

  FPDF_BStr_Set(&bst, "clams", 5);
  EXPECT_STREQ("clams", bst.str);
  EXPECT_EQ(5, bst.len);

  FPDF_BStr_Set(&bst, "clams", 1);
  EXPECT_STREQ("c", bst.str);
  EXPECT_EQ(1, bst.len);

  FPDF_BStr_Set(&bst, "clams", 0);
  EXPECT_FALSE(bst.str);
  EXPECT_EQ(0, bst.len);

  FPDF_BStr_Clear(&bst);
}

#endif  // PDF_ENABLE_XFA
