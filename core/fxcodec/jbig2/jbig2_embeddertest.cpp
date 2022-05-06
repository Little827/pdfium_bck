// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_defaultrenderdevice.h"
#include "public/cpp/fpdf_scopers.h"
#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

class JBig2EmbedderTest : public EmbedderTest {};

TEST_F(JBig2EmbedderTest, Bug_631912) {
  // TODO(crbug.com/pdfium/11): Fix this test and enable.
#if defined(_SKIA_SUPPORT_)
  if (CFX_DefaultRenderDevice::SkiaIsDefaultRenderer())
    return;
#endif

  // Test jbig2 image in PDF file can be loaded successfully.
  // Should not crash.
  ASSERT_TRUE(OpenDocument("bug_631912.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  ScopedFPDFBitmap bitmap = RenderLoadedPage(page);
  CompareBitmap(bitmap.get(), 691, 432, "726c2b8c89df0ab40627322d1dddd521");
  UnloadPage(page);
}
