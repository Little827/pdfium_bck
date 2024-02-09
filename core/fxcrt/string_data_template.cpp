// Copyright 2020 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/string_data_template.h"

#include <string.h>

#include <new>

#include "core/fxcrt/fx_memcpy_wrappers.h"
#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/span_util.h"
#include "third_party/base/check.h"
#include "third_party/base/check_op.h"
#include "third_party/base/compiler_specific.h"

namespace fxcrt {

// static
template <typename CharType>
RetainPtr<StringDataTemplate<CharType>> StringDataTemplate<CharType>::Create(
    size_t nLen) {
  DCHECK_GT(nLen, 0u);

  // Calculate space needed for the fixed portion of the struct plus the
  // NUL char that is not included in |m_nAllocLength|.
  int overhead = offsetof(StringDataTemplate, m_String) + sizeof(CharType);
  FX_SAFE_SIZE_T nSize = nLen;
  nSize *= sizeof(CharType);
  nSize += overhead;

  // Now round to an 16-byte boundary, assuming the underlying allocator is most
  // likely PartitionAlloc, which has 16 byte chunks. This will help with cases
  // where we can save a re-alloc when adding a few characters to a string by
  // using this otherwise wasted space.
  nSize += 15;
  nSize &= ~15;
  size_t totalSize = nSize.ValueOrDie();
  size_t usableLen = (totalSize - overhead) / sizeof(CharType);
  DCHECK(usableLen >= nLen);

  void* pData = FX_StringAlloc(char, totalSize);
  return pdfium::WrapRetain(new (pData) StringDataTemplate(nLen, usableLen));
}

// static
template <typename CharType>
RetainPtr<StringDataTemplate<CharType>> StringDataTemplate<CharType>::Create(
    pdfium::span<const CharType> str) {
  RetainPtr<StringDataTemplate> result = Create(str.size());
  result->CopyContents(str);
  return result;
}

template <typename CharType>
void StringDataTemplate<CharType>::Release() {
  if (--m_nRefs <= 0)
    FX_StringFree(this);
}

template <typename CharType>
void StringDataTemplate<CharType>::CopyContents(
    const StringDataTemplate& other) {
  fxcrt::spancpy(capacity(), other.capacity().first(other.m_nDataLength + 1));
}

template <typename CharType>
void StringDataTemplate<CharType>::CopyContents(
    pdfium::span<const CharType> str) {
  fxcrt::spancpy(capacity(), str);
  capacity()[str.size()] = 0;
}

template <typename CharType>
void StringDataTemplate<CharType>::CopyContentsAt(
    size_t offset,
    pdfium::span<const CharType> str) {
  fxcrt::spancpy(capacity().subspan(offset), str);
  capacity()[offset + str.size()] = 0;
}

template <typename CharType>
StringDataTemplate<CharType>::StringDataTemplate(size_t dataLen,
                                                 size_t allocLen)
    : m_nDataLength(dataLen), m_nAllocLength(allocLen) {
  capacity()[dataLen] = 0;
}

template class StringDataTemplate<char>;
template class StringDataTemplate<wchar_t>;

}  // namespace fxcrt
