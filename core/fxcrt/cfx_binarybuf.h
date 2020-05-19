// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_BINARYBUF_H_
#define CORE_FXCRT_CFX_BINARYBUF_H_

#include <memory>

#include "core/fxcrt/fx_memory_wrappers.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "third_party/base/span.h"

class CFX_BinaryBuf {
 public:
  CFX_BinaryBuf();
  virtual ~CFX_BinaryBuf();

  pdfium::span<uint8_t> GetSpan();
  pdfium::span<const uint8_t> GetSpan() const;
  uint8_t* GetBuffer() const { return buffer_.get(); }
  size_t GetSize() const { return data_size_; }
  virtual size_t GetLength() const;
  bool IsEmpty() const { return GetLength() == 0; }

  void Clear();
  void SetAllocStep(size_t step) { alloc_step_ = step; }
  void EstimateSize(size_t size);
  void AppendSpan(pdfium::span<const uint8_t> span);
  void AppendBlock(const void* pBuf, size_t size);
  void AppendString(const ByteString& str) {
    AppendBlock(str.c_str(), str.GetLength());
  }

  void AppendByte(uint8_t byte) {
    ExpandBuf(1);
    buffer_.get()[data_size_++] = byte;
  }

  void Delete(size_t start_index, size_t count);

  // Releases ownership of |buffer_| and returns it.
  std::unique_ptr<uint8_t, FxFreeDeleter> DetachBuffer();

 protected:
  void ExpandBuf(size_t size);

  size_t alloc_step_ = 0;
  size_t alloc_size_ = 0;
  size_t data_size_ = 0;
  std::unique_ptr<uint8_t, FxFreeDeleter> buffer_;
};

#endif  // CORE_FXCRT_CFX_BINARYBUF_H_
