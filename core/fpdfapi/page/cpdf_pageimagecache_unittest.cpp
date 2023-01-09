// Copyright 2022 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/page/cpdf_image.h"
#include "core/fpdfapi/page/cpdf_imageobject.h"
#include "core/fpdfapi/page/cpdf_pageimagecache.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "public/cpp/fpdf_scopers.h"
#include "public/fpdfview.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/utils/file_util.h"

TEST(CPDFPageImageCache, RenderBug1924) {
  // If you render a page with a JPEG2000 image as a thumbnail (small picture)
  // first, the image that gets cached has a low resolution. If you afterwards
  // render it full-size, you should get a larger image - the image cache will
  // be regenerate.

  FPDF_InitLibrary();
  {
    ScopedFPDFDocument doc;
    FileAccessForTesting file_access("jpx_lzw.pdf");
    doc.reset(FPDF_LoadCustomDocument(&file_access, nullptr));
    ASSERT_TRUE(doc);
    FPDF_PAGE page = FPDF_LoadPage(doc.get(), 0);
    ASSERT_TRUE(page);
    CPDF_Page* cpage = CPDFPageFromFPDFPage(page);
    ASSERT_TRUE(cpage);

    CPDF_PageImageCache* page_image_cache = cpage->GetPageImageCache();
    ASSERT_TRUE(page_image_cache);

    FPDF_PAGEOBJECT image_object = FPDFPage_GetObject(page, 0);
    ASSERT_TRUE(image_object);
    ASSERT_EQ(FPDFPageObj_GetType(image_object), FPDF_PAGEOBJ_IMAGE);
    CPDF_ImageObject* image =
        CPDFPageObjectFromFPDFPageObject(image_object)->AsImage();
    ASSERT_TRUE(image);

    // Render with small scale.
    bool should_continue = page_image_cache->StartGetCachedBitmap(
        image->GetImage(), nullptr, cpage->GetMutablePageResources(), true,
        CPDF_ColorSpace::Family::kICCBased, false, {50, 50});
    while (should_continue)
      should_continue = page_image_cache->Continue(nullptr);

    RetainPtr<CFX_DIBBase> bitmap_small = page_image_cache->DetachCurBitmap();

    // And render with large scale.
    should_continue = page_image_cache->StartGetCachedBitmap(
        image->GetImage(), nullptr, cpage->GetMutablePageResources(), true,
        CPDF_ColorSpace::Family::kICCBased, false, {100, 100});
    while (should_continue)
      should_continue = page_image_cache->Continue(nullptr);

    RetainPtr<CFX_DIBBase> bitmap_large = page_image_cache->DetachCurBitmap();

    ASSERT_GT(bitmap_large->GetWidth(), bitmap_small->GetWidth());
    ASSERT_GT(bitmap_large->GetHeight(), bitmap_small->GetHeight());

    FPDF_ClosePage(page);
  }
  FPDF_DestroyLibrary();
}