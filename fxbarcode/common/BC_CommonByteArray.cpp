// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com
// Original code is licensed as follows:
/*
 * Copyright 2008 ZXing authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "fxbarcode/common/BC_CommonByteArray.h"

#include <algorithm>
#include <utility>

#include "core/fxcrt/fx_memory.h"

CBC_CommonByteArray::CBC_CommonByteArray() = default;

CBC_CommonByteArray::CBC_CommonByteArray(int32_t size)
    : m_size(size), m_bytes(FX_Alloc(uint8_t, size)) {
  memset(m_bytes.get(), 0, size);
}

CBC_CommonByteArray::CBC_CommonByteArray(uint8_t* byteArray, int32_t size)
    : m_size(size), m_index(size), m_bytes(FX_Alloc(uint8_t, size)) {
  memcpy(m_bytes.get(), byteArray, size);
}

CBC_CommonByteArray::~CBC_CommonByteArray() = default;

void CBC_CommonByteArray::AppendByte(int32_t value) {
  if (m_size == 0 || m_index >= m_size) {
    int32_t newSize = std::max(32, m_size << 1);
    Reserve(newSize);
  }
  m_bytes.get()[m_index] = (uint8_t)value;
  m_index++;
}
void CBC_CommonByteArray::Reserve(int32_t capacity) {
  if (!m_bytes || m_size < capacity) {
    std::unique_ptr<uint8_t, FxFreeDeleter> newArray(
        FX_Alloc(uint8_t, capacity));
    if (m_bytes) {
      memcpy(newArray.get(), m_bytes.get(), m_size);
      memset(newArray.get() + m_size, 0, capacity - m_size);
    } else {
      memset(newArray.get(), 0, capacity);
    }
    m_bytes = std::move(newArray);
    m_size = capacity;
  }
}
void CBC_CommonByteArray::Set(const uint8_t* source,
                              int32_t offset,
                              int32_t count) {
  m_size = count;
  m_index = count;
  m_bytes.reset(FX_Alloc(uint8_t, count));
  memcpy(m_bytes.get(), source + offset, count);
}
void CBC_CommonByteArray::Set(std::vector<uint8_t>* source,
                              int32_t offset,
                              int32_t count) {
  m_size = count;
  m_index = count;
  m_bytes.reset(FX_Alloc(uint8_t, count));
  for (int32_t i = 0; i < count; i++)
    m_bytes.get()[i] = (*source)[i + offset];
}
