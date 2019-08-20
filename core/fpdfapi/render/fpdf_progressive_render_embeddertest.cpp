// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

class MockPause : public IFSDK_PAUSE {
 public:
  explicit MockPause(bool should_pause) : should_pause_(should_pause) {
    IFSDK_PAUSE::version = 1;
    IFSDK_PAUSE::user = nullptr;
    IFSDK_PAUSE::NeedToPauseNow = Pause_NeedToPauseNow;
  }
  ~MockPause() = default;

  static FPDF_BOOL Pause_NeedToPauseNow(IFSDK_PAUSE* param) {
    return static_cast<MockPause*>(param)->should_pause_;
  }

 private:
  bool should_pause_ = false;
};

class FPDFProgressiveRenderEmbedderTest : public EmbedderTest {};

TEST_F(FPDFProgressiveRenderEmbedderTest, RenderWithoutPause) {
  // Test rendering of page content using progressive render APIs
  // without pausing the rendering.
  EXPECT_TRUE(OpenDocument("annotation_stamp_with_ap.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  MockPause pause(false);
  EXPECT_TRUE(StartRenderLoadedPage(page, &pause));
  ScopedFPDFBitmap bitmap = FinishRenderPage(page);
  CompareBitmap(bitmap.get(), 595, 842, "649d6792ea50faf98c013c2d81710595");
  UnloadPage(page);
}

TEST_F(FPDFProgressiveRenderEmbedderTest, RenderWithPause) {
  // Test rendering of page content using progressive render APIs
  // with pause in rendering.
  EXPECT_TRUE(OpenDocument("annotation_stamp_with_ap.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  MockPause pause(true);
  bool render_done = StartRenderLoadedPage(page, &pause);
  EXPECT_FALSE(render_done);

  while (!render_done) {
    render_done = ContinueRenderPage(page, &pause);
  }
  ScopedFPDFBitmap bitmap = FinishRenderPage(page);
  CompareBitmap(bitmap.get(), 595, 842, "649d6792ea50faf98c013c2d81710595");
  UnloadPage(page);
}

TEST_F(FPDFProgressiveRenderEmbedderTest, RenderAnnotWithPause) {
  // Test rendering of the page with annotations using progressive render APIs
  // with pause in rendering.
  EXPECT_TRUE(OpenDocument("annotation_stamp_with_ap.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  MockPause pause(true);
  bool render_done = StartRenderLoadedPageWithFlags(page, &pause, FPDF_ANNOT);
  EXPECT_FALSE(render_done);

  while (!render_done) {
    render_done = ContinueRenderPage(page, &pause);
  }
  ScopedFPDFBitmap bitmap = FinishRenderPage(page);
  CompareBitmap(bitmap.get(), 595, 842, "6aa001a77ec05d0f1b0d1d22e28744d4");
  UnloadPage(page);
}

TEST_F(FPDFProgressiveRenderEmbedderTest, RenderFormsWithPause) {
  // Test rendering of the page with forms using progressive render APIs
  // with pause in rendering.
  EXPECT_TRUE(OpenDocument("text_form.pdf"));
  FPDF_PAGE page = LoadPage(0);
  ASSERT_TRUE(page);
  MockPause pause(true);
  bool render_done = StartRenderLoadedPage(page, &pause);
  EXPECT_FALSE(render_done);

  while (!render_done) {
    render_done = ContinueRenderPage(page, &pause);
  }
  ScopedFPDFBitmap bitmap = FinishRenderPageWithForms(page, form_handle_);
  CompareBitmap(bitmap.get(), 300, 300, "d3204faa62b607f0bd3893c9c22cabcb");
  UnloadPage(page);
}
