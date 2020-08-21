// Copyright 2015 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test_environment.h"

#include "public/fpdfview.h"

#ifdef PDF_ENABLE_V8
#include "testing/v8_test_environment.h"
#endif  // PDF_ENABLE_V8

EmbedderTestEnvironment::EmbedderTestEnvironment() = default;

EmbedderTestEnvironment::~EmbedderTestEnvironment() = default;

void EmbedderTestEnvironment::SetUp() {
  FPDF_LIBRARY_CONFIG config;
  config.version = 3;
  config.m_pUserFontPaths = nullptr;
  config.m_v8EmbedderSlot = 0;
  config.m_pPlatform = nullptr;
#ifdef PDF_ENABLE_V8
  config.m_pIsolate = V8TestEnvironment::GetInstance()->platform();
  ;
  config.m_pPlatform = V8TestEnvironment::GetInstance()->platform();
#else   // PDF_ENABLE_V8
  config.m_pIsolate = nullptr;
  config.m_pPlatform = nullptr;
#endif  // PDF_ENABLE_V8

  FPDF_InitLibraryWithConfig(&config);
}

void EmbedderTestEnvironment::TearDown() {
  FPDF_DestroyLibrary();
}
