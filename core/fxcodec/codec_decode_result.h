// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCODEC_CODEC_DECODE_RESULT_H_
#define CORE_FXCODEC_CODEC_DECODE_RESULT_H_

#include <stdint.h>

#include <memory>

#include "core/fxcrt/fx_memory_wrappers.h"

namespace fxcodec {

struct CodecDecodeResult {
  CodecDecodeResult(std::unique_ptr<uint8_t, FxFreeDeleter> data,
                    uint32_t size,
                    uint32_t offset);
  ~CodecDecodeResult();

  // TODO(crbug.com/pdfium/1872): Replace with DataVector.
  std::unique_ptr<uint8_t, FxFreeDeleter> data;
  uint32_t size;
  uint32_t offset;
};

}  // namespace fxcodec

using CodecDecodeResult = fxcodec::CodecDecodeResult;

#endif  // CORE_FXCODEC_CODEC_DECODE_RESULT_H_
