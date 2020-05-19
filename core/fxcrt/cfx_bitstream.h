// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_BITSTREAM_H_
#define CORE_FXCRT_CFX_BITSTREAM_H_

#include <stdint.h>

#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/span.h"

class CFX_BitStream {
 public:
  explicit CFX_BitStream(pdfium::span<const uint8_t> pData);
  ~CFX_BitStream();

  void ByteAlign();

  bool IsEOF() const { return bit_pos_ >= bit_size_; }
  uint32_t GetPos() const { return bit_pos_; }
  uint32_t GetBits(uint32_t nBits);

  void SkipBits(uint32_t nBits) { bit_pos_ += nBits; }
  void Rewind() { bit_pos_ = 0; }

  uint32_t BitsRemaining() const {
    return bit_size_ >= bit_pos_ ? bit_size_ - bit_pos_ : 0;
  }

 private:
  uint32_t bit_pos_;
  uint32_t bit_size_;
  UnownedPtr<const uint8_t> data_;
};

#endif  // CORE_FXCRT_CFX_BITSTREAM_H_
