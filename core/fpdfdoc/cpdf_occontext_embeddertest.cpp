// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/test_support.h"

using CPDFOCContextEmbedderTest = EmbedderTest;

TEST_F(CPDFOCContextEmbedderTest, UseCorrectDefaultLayer) {
  EXPECT_TRUE(OpenDocument("default_layer_configuration.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  ScopedFPDFBitmap bitmap = RenderLoadedPage(page);
  CompareBitmap(bitmap.get(), 612, 792, "df1d54b5155d836275e76e78c467369e");
  UnloadPage(page);
}
