// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PDFIUM_LPM_FUZZ_STUB_H_
#define TESTING_FUZZERS_PDFIUM_LPM_FUZZ_STUB_H_

// Don't use FDPF_EXPORT so header can be included outside of PDFium.
#if defined(_WIN32)
#define FUZZER_EXPORT_FUNCTION __declspec(dllexport)
#else
#define FUZZER_EXPORT_FUNCTION __attribute__((visibility("default")))
#endif

// LPM defines LLVMFuzzerTestOneInput, this function should be used by the LPM
// harness to pass the deserialized proto to PDFium.
FUZZER_EXPORT_FUNCTION void FuzzPdf(const char* pdf, size_t size);

#undef FUZZER_EXPORT_FUNCTION

#endif  // TESTING_FUZZERS_PDFIUM_LPM_FUZZ_STUB_H_
