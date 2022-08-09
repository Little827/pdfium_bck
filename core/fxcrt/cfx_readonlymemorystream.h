// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_READONLYMEMORYSTREAM_H_
#define CORE_FXCRT_CFX_READONLYMEMORYSTREAM_H_

#include <memory>
#include <vector>

#include "core/fxcrt/bytestring.h"
#include "core/fxcrt/fx_memory_wrappers.h"
#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/retain_ptr.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/base/span.h"

class CFX_ReadOnlyMemoryStream final : public IFX_SeekableReadStream {
 public:
  CONSTRUCT_VIA_MAKE_RETAIN;

  // IFX_SeekableReadStream:
  FX_FILESIZE GetSize() override;
  bool ReadBlockAtOffset(void* buffer,
                         FX_FILESIZE offset,
                         size_t size) override;

 private:
  using SpanType = pdfium::span<const uint8_t>;
  using VectorType = std::vector<uint8_t, FxAllocAllocator<uint8_t>>;
  // TODO(crbug.com/pdfium/1872): Remove this.
  using UniquePtrType = std::unique_ptr<uint8_t, FxFreeDeleter>;

  explicit CFX_ReadOnlyMemoryStream(SpanType span);
  explicit CFX_ReadOnlyMemoryStream(VectorType data);
  explicit CFX_ReadOnlyMemoryStream(ByteString data);
  CFX_ReadOnlyMemoryStream(UniquePtrType data, size_t size);
  ~CFX_ReadOnlyMemoryStream() override;

  const absl::variant<absl::monostate, VectorType, UniquePtrType, ByteString>
      data_;
  const SpanType span_;
};

#endif  // CORE_FXCRT_CFX_READONLYMEMORYSTREAM_H_
