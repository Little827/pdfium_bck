// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_
#define TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_

#include <memory>

#include "public/fpdf_ext.h"
#include "public/fpdfview.h"

#ifdef PDF_ENABLE_V8
#include "v8/include/v8-platform.h"
#include "v8/include/v8.h"
#ifdef PDF_ENABLE_XFA
#include "fxjs/gc/heap.h"
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8

// Initializes the library once for all runs of the fuzzer.
struct PDFFuzzerInitPublic {
  static PDFFuzzerInitPublic* GetInstance();

  PDFFuzzerInitPublic();
  ~PDFFuzzerInitPublic();

#ifdef PDF_ENABLE_V8
#ifdef PDF_ENABLE_XFA
  cppgc::Heap* GetHeap() { return heap.get(); }
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8

 private:
  FPDF_LIBRARY_CONFIG config;
  UNSUPPORT_INFO unsupport_info;
#ifdef PDF_ENABLE_V8
  std::unique_ptr<v8::Platform> platform;
  v8::StartupData snapshot_blob;
#ifdef PDF_ENABLE_XFA
  FXGCScopedHeap heap;
#endif  // PDF_ENABLE_XFA
#endif  // PDF_ENABLE_V8
};

#endif  // TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_
