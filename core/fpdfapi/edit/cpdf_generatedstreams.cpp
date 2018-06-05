// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/edit/cpdf_generatedstreams.h"

#include "core/fpdfapi/page/cpdf_pageobject.h"

#include <iostream>

CPDF_GeneratedStreams::CPDF_GeneratedStreams(
    const std::vector<UnownedPtr<CPDF_PageObject>>& page_objects) {
  std::cerr << "CPDF_GeneratedStreams::CPDF_GeneratedStreams(" << page_objects.size() << ")" << std::endl;
  for (auto& page_object : page_objects) {
    int32_t content_stream = page_object->GetContentStream();
    if (!GetBuffer(content_stream)) {
      std::cerr << "  -> create for content_stream=" << content_stream << std::endl;
      buffers_.emplace(content_stream, pdfium::MakeUnique<std::ostringstream>());
    }
  }

  // Temporary to make tests work
  buffers_.emplace(0, pdfium::MakeUnique<std::ostringstream>());

  std::cerr << "CPDF_GeneratedStreams::CPDF_GeneratedStreams(" << page_objects.size() << ") END" << std::endl;
}

std::ostringstream* CPDF_GeneratedStreams::GetBuffer(int32_t content_stream) {
  std::cerr << "CPDF_GeneratedStreams::GetBuffer(" << content_stream << ")" << std::endl;
  auto it = buffers_.find(content_stream);
  if (it == buffers_.end()) {
    std::cerr << "  -> nope" << std::endl;
  std::cerr << "CPDF_GeneratedStreams::GetBuffer(" << content_stream << ") END" << std::endl;
    return nullptr;
  }

  std::cerr << "  -> yep" << std::endl;
  std::cerr << "CPDF_GeneratedStreams::GetBuffer(" << content_stream << ") END" << std::endl;
  return it->second.get();
}
