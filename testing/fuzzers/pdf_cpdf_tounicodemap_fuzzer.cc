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
#include "core/fxcrt/widestring.h"
#include "testing/fuzzers/pdfium_fuzzer_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static constexpr size_t kParameterSize = 4 + sizeof(unsigned short);
  if (size <= kParameterSize)
    return 0;

  // Limit data size to prevent fuzzer timeout.
  static constexpr size_t kMaxDataSize = 256 * 1024;
  if (size > kParameterSize + kMaxDataSize)
    return 0;

  wchar_t char_for_reverse_lookup = WideString::FromUTF16LE(
      reinterpret_cast<const unsigned short*>(data), 1)[0];
  uint32_t charcode_to_lookup = GetInteger(data + sizeof(unsigned short));

  FuzzedDataProvider data_provider(data + kParameterSize,
                                   size - kParameterSize);
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
