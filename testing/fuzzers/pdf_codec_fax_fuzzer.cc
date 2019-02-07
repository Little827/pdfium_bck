// Copyright 2016 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>

#include "core/fxcodec/codec/ccodec_faxmodule.h"
#include "core/fxcodec/codec/ccodec_scanlinedecoder.h"
#include "testing/fuzzers/pdfium_fuzzer_helper.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static constexpr size_t kParameterSize = 21;
  if (size < kParameterSize)
    return 0;

  // Limit data size to prevent fuzzer timeout.
  static constexpr size_t kMaxDataSize = 256 * 1024;
  if (size > kParameterSize + kMaxDataSize)
    return 0;

  int width = PDFiumFuzzerHelper::GetInteger(data);
  int height = PDFiumFuzzerHelper::GetInteger(data + 4);
  int K = PDFiumFuzzerHelper::GetInteger(data + 8);
  int Columns = PDFiumFuzzerHelper::GetInteger(data + 12);
  int Rows = PDFiumFuzzerHelper::GetInteger(data + 16);
  bool EndOfLine = !(data[20] & 0x01);
  bool ByteAlign = !(data[20] & 0x02);
  // This controls if CCodec_FaxDecoder::InvertBuffer() gets called. The method
  // is not interesting, and calling it doubles the runtime.
  const bool kBlackIs1 = false;
  data += kParameterSize;
  size -= kParameterSize;

  CCodec_FaxModule fax_module;
  std::unique_ptr<CCodec_ScanlineDecoder> decoder(
      fax_module.CreateDecoder({data, size}, width, height, K, EndOfLine,
                               ByteAlign, kBlackIs1, Columns, Rows));

  if (decoder) {
    int line = 0;
    while (decoder->GetScanline(line))
      line++;
  }

  return 0;
}
