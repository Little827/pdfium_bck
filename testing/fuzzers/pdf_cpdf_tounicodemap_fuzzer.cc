// Copyright 2021 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <vector>

#include "core/fpdfapi/font/cpdf_tounicodemap.h"
#include "core/fpdfapi/page/cpdf_streamparser.h"
#include "core/fpdfapi/parser/cpdf_object.h"
#include "core/fpdfapi/parser/cpdf_stream.h"
#include "testing/fuzzers/pdfium_fuzzer_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  uint32_t charcode_to_lookup = GetInteger(data);
  wchar_t char_for_reverse_lookup = GetInteger(data + 4);
  // WideString string_to_lookup(char_for_reverse_lookup);

  FuzzedDataProvider data_provider(data + 6, size - 6);
  std::vector<uint8_t> remaining =
      data_provider.ConsumeRemainingBytes<uint8_t>();
  if (remaining.empty())
    return 0;

  CPDF_StreamParser parser(remaining);
  const RetainPtr<CPDF_Object>& object = parser.GetObject();

  auto* stream = static_cast<CPDF_Stream*>(object.Get());
  auto to_unicode_map = std::make_unique<CPDF_ToUnicodeMap>(stream);
  to_unicode_map->Lookup(charcode_to_lookup);
  to_unicode_map->ReverseLookup(char_for_reverse_lookup);
  return 0;
}
