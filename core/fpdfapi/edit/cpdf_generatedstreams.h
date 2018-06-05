// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_EDIT_CPDF_GENERATEDSTREAMS_H_
#define CORE_FPDFAPI_EDIT_CPDF_GENERATEDSTREAMS_H_

#include <map>
#include <sstream>
#include <vector>

#include "core/fxcrt/unowned_ptr.h"

class CPDF_PageObject;

class CPDF_GeneratedStreams {
 public:
  CPDF_GeneratedStreams(const std::vector<UnownedPtr<CPDF_PageObject>>& page_objects);
  ~CPDF_GeneratedStreams() = default;
  std::ostringstream* GetBuffer(int32_t content_stream);

 private:
  std::map<int32_t, std::unique_ptr<std::ostringstream>> buffers_;
};

#endif  // CORE_FPDFAPI_EDIT_CPDF_GENERATEDSTREAMS_H_
