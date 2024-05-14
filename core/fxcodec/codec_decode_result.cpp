// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcodec/codec_decode_result.h"

#include <utility>

namespace fxcodec {

CodecDecodeResult::CodecDecodeResult(
    std::unique_ptr<uint8_t, FxFreeDeleter> data,
    uint32_t size,
    uint32_t offset)
    : data(std::move(data)), size(size), offset(offset) {}

CodecDecodeResult::~CodecDecodeResult() = default;

}  // namespace fxcodec
