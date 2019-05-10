// Copyright 2017 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string.h>

#include "public/fpdfview.h"

namespace {
FPDF_LIBRARY_CONFIG config;
}  // namespace

FPDF_EXPORT void InitializePdfiumForFuzzer() {
  memset(&config, '\0', sizeof(config));
  config.version = 2;
  config.m_pUserFontPaths = nullptr;
  config.m_pIsolate = nullptr;
  config.m_v8EmbedderSlot = 0;
  FPDF_InitLibraryWithConfig(&config);
}
