// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/pdf_test_environment.h"

#include "core/fxge/cfx_gemodule.h"

#ifdef PDF_ENABLE_XFA
#include "xfa/fgas/font/cfgas_gemodule.h"
#endif  // PDF_ENABLE_XFA

PDFTestEnvironment::PDFTestEnvironment() = default;

PDFTestEnvironment::~PDFTestEnvironment() = default;

// testing::Environment:
void PDFTestEnvironment::SetUp() {
  CFX_GEModule::Create(nullptr);
#ifdef PDF_ENABLE_XFA
  CFGAS_GEModule::Create();
#endif  // PDF_ENABLE_XFA
}

void PDFTestEnvironment::TearDown() {
#ifdef PDF_ENABLE_XFA
  CFGAS_GEModule::Destroy();
#endif  // PDF_ENABLE_XFA
  CFX_GEModule::Destroy();
}
