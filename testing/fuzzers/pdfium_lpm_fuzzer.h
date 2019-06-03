// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TESTING_FUZZERS_PDFIUM_LPM_FUZZER_H_
#define TESTING_FUZZERS_PDFIUM_LPM_FUZZER_H_

__attribute__((visibility("default"))) void FuzzPdf(const char* pdf,
                                                    size_t size);

#endif  // TESTING_FUZZERS_PDFIUM_LPM_FUZZER_H_
