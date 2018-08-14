// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_memorystream.h"

#include <algorithm>
#include <utility>

#include "core/fxcrt/fx_safe_types.h"

CFX_MemoryStream::CFX_MemoryStream() : m_nTotalSize(0), m_nCurSize(0) {}

CFX_MemoryStream::CFX_MemoryStream(
    std::unique_ptr<uint8_t, FxFreeDeleter> pBuffer,
    size_t nSize)
    : m_data(std::move(pBuffer)), m_nTotalSize(nSize), m_nCurSize(nSize) {}

CFX_MemoryStream::~CFX_MemoryStream() = default;

FX_FILESIZE CFX_MemoryStream::GetSize() {
  return static_cast<FX_FILESIZE>(m_nCurSize);
}

FX_FILESIZE CFX_MemoryStream::GetPosition() {
  return static_cast<FX_FILESIZE>(m_nCurPos);
}

bool CFX_MemoryStream::IsEOF() {
  return m_nCurPos >= m_nCurSize;
}

bool CFX_MemoryStream::ReadBlock(void* buffer,
                                 FX_FILESIZE offset,
                                 size_t size) {
  if (!buffer || !size || offset < 0)
    return false;

  FX_SAFE_SIZE_T newPos = size;
  newPos += offset;
  if (!newPos.IsValid() || newPos.ValueOrDie() > m_nCurSize)
    return false;

  m_nCurPos = newPos.ValueOrDie();
  memcpy(buffer, &GetBuffer()[offset], size);
  return true;
}

size_t CFX_MemoryStream::ReadBlock(void* buffer, size_t size) {
  if (m_nCurPos >= m_nCurSize)
    return 0;

  size_t nRead = std::min(size, m_nCurSize - m_nCurPos);
  if (!ReadBlock(buffer, static_cast<FX_FILESIZE>(m_nCurPos), nRead))
    return 0;

  return nRead;
}

bool CFX_MemoryStream::WriteBlock(const void* buffer,
                                  FX_FILESIZE offset,
                                  size_t size) {
  if (!buffer || !size || offset < 0)
    return false;

  FX_SAFE_SIZE_T newPos = size;
  newPos += offset;
  if (!newPos.IsValid())
    return false;

  m_nCurPos = newPos.ValueOrDie();
  if (m_nCurPos > m_nTotalSize) {
    static constexpr size_t kBlockSize = 64 * 1024;
    m_nTotalSize = (m_nCurPos + kBlockSize - 1) / kBlockSize * kBlockSize;
    if (m_data)
      m_data.reset(FX_Realloc(uint8_t, m_data.get(), m_nTotalSize));
    else
      m_data.reset(FX_Alloc(uint8_t, m_nTotalSize));
  }

  memcpy(&m_data.get()[offset], buffer, size);
  m_nCurSize = std::max(m_nCurSize, m_nCurPos);

  return true;
}

bool CFX_MemoryStream::Flush() {
  return true;
}
