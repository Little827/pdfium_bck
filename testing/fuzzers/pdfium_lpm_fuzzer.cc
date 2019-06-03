// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "testing/fuzzers/pdfium_fuzzer_helper.h"
#include "testing/fuzzers/pdfium_lpm_fuzzer.h"

class PDFiumFuzzer : public PDFiumFuzzerHelper {
 public:
  PDFiumFuzzer() = default;
  ~PDFiumFuzzer() override = default;

  int GetFormCallbackVersion() const override { return 1; }
};

int FuzzPdf(const char* pdf, size_t size) {
  PDFiumFuzzer fuzzer;
  fuzzer.RenderPdf(pdf, size);
  return 0;
}
