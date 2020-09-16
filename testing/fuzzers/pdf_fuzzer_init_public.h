// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_
#define TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_

#include <memory>

#include "public/fpdf_ext.h"
#include "public/fpdfview.h"
#include "testing/fuzzers/process_state.h"

#ifdef PDF_ENABLE_V8
#include "fxjs/cfx_v8.h"
#include "v8/include/v8-platform.h"
#include "v8/include/v8.h"
#endif  // PDF_ENABLE_V8

// Initializes the library once for all runs of the fuzzer.
class PDFFuzzerInitPublic {
 public:
  PDFFuzzerInitPublic();
  ~PDFFuzzerInitPublic();

 private:
  FPDF_LIBRARY_CONFIG config_;
  UNSUPPORT_INFO unsupport_info_;
#ifdef PDF_ENABLE_V8
  v8::StartupData snapshot_blob_;
  std::unique_ptr<v8::Platform> platform_;
  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator_;
  std::unique_ptr<v8::Isolate, CFX_V8IsolateDeleter> isolate_;
#endif  // PDF_ENABLE_V8

  std::unique_ptr<ProcessState> process_state_;
};

#endif  // TESTING_FUZZERS_PDF_FUZZER_INIT_PUBLIC_H_
