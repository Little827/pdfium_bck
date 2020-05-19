// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_memorystream.h"

#include <algorithm>
#include <utility>

#include "core/fxcrt/fx_safe_types.h"

CFX_MemoryStream::CFX_MemoryStream() : total_size_(0), cur_size_(0) {}

CFX_MemoryStream::CFX_MemoryStream(
    std::unique_ptr<uint8_t, FxFreeDeleter> pBuffer,
    size_t nSize)
    : data_(std::move(pBuffer)), total_size_(nSize), cur_size_(nSize) {}

CFX_MemoryStream::~CFX_MemoryStream() = default;

FX_FILESIZE CFX_MemoryStream::GetSize() {
  return static_cast<FX_FILESIZE>(cur_size_);
}

bool CFX_MemoryStream::IsEOF() {
  return cur_pos_ >= static_cast<size_t>(GetSize());
}

FX_FILESIZE CFX_MemoryStream::GetPosition() {
  return static_cast<FX_FILESIZE>(cur_pos_);
}

bool CFX_MemoryStream::Flush() {
  return true;
}

bool CFX_MemoryStream::ReadBlockAtOffset(void* buffer,
                                         FX_FILESIZE offset,
                                         size_t size) {
  if (!buffer || offset < 0 || !size)
    return false;

  FX_SAFE_SIZE_T newPos = size;
  newPos += offset;
  if (!newPos.IsValid() || newPos.ValueOrDefault(0) == 0 ||
      newPos.ValueOrDie() > cur_size_) {
    return false;
  }

  cur_pos_ = newPos.ValueOrDie();
  memcpy(buffer, &GetBuffer()[offset], size);
  return true;
}

size_t CFX_MemoryStream::ReadBlock(void* buffer, size_t size) {
  if (cur_pos_ >= cur_size_)
    return 0;

  size_t nRead = std::min(size, cur_size_ - cur_pos_);
  if (!ReadBlockAtOffset(buffer, static_cast<int32_t>(cur_pos_), nRead))
    return 0;

  return nRead;
}

bool CFX_MemoryStream::WriteBlockAtOffset(const void* buffer,
                                          FX_FILESIZE offset,
                                          size_t size) {
  if (!buffer || offset < 0 || !size)
    return false;

  FX_SAFE_SIZE_T safe_new_pos = size;
  safe_new_pos += offset;
  if (!safe_new_pos.IsValid())
    return false;

  size_t new_pos = safe_new_pos.ValueOrDie();
  if (new_pos > total_size_) {
    static constexpr size_t kBlockSize = 64 * 1024;
    FX_SAFE_SIZE_T new_size = new_pos;
    new_size *= 2;
    new_size += (kBlockSize - 1);
    new_size /= kBlockSize;
    new_size *= kBlockSize;
    if (!new_size.IsValid())
      return false;

    total_size_ = new_size.ValueOrDie();
    if (data_)
      data_.reset(FX_Realloc(uint8_t, data_.release(), total_size_));
    else
      data_.reset(FX_Alloc(uint8_t, total_size_));
  }
  cur_pos_ = new_pos;

  memcpy(&data_.get()[offset], buffer, size);
  cur_size_ = std::max(cur_size_, cur_pos_);

  return true;
}
