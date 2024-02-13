// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/string_template.h"

#include <string.h>

#include <algorithm>
#include <new>
#include <utility>

#include "core/fxcrt/fx_memcpy_wrappers.h"
#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/span_util.h"
#include "third_party/base/check.h"
#include "third_party/base/check_op.h"
#include "third_party/base/containers/span.h"

namespace fxcrt {

template <typename CharType>
StringTemplate<CharType>::StringTemplate(const CharType* pStr, size_t nLen) {
  if (nLen) {
    m_pData = StringData::Create({pStr, nLen});
  }
}

template <typename CharType>
StringTemplate<CharType>::StringTemplate(CharType ch) {
  m_pData = StringData::Create(1);
  m_pData->m_String[0] = ch;
}

template <typename CharType>
StringTemplate<CharType>::StringTemplate(StringViewTemplate<CharType> bstrc) {
  if (!bstrc.IsEmpty()) {
    m_pData = StringData::Create(bstrc.span());
  }
}

template <typename CharType>
StringTemplate<CharType>::StringTemplate(StringViewTemplate<CharType> str1,
                                         StringViewTemplate<CharType> str2) {
  FX_SAFE_SIZE_T nSafeLen = str1.GetLength();
  nSafeLen += str2.GetLength();

  size_t nNewLen = nSafeLen.ValueOrDie();
  if (nNewLen == 0) {
    return;
  }

  m_pData = StringData::Create(nNewLen);
  m_pData->CopyContents(str1.span());
  m_pData->CopyContentsAt(str1.GetLength(), str2.span());
}

template <typename CharType>
StringTemplate<CharType>::StringTemplate(
    const std::initializer_list<StringViewTemplate<CharType>>& list) {
  FX_SAFE_SIZE_T nSafeLen = 0;
  for (const auto& item : list) {
    nSafeLen += item.GetLength();
  }

  size_t nNewLen = nSafeLen.ValueOrDie();
  if (nNewLen == 0) {
    return;
  }

  m_pData = StringData::Create(nNewLen);

  size_t nOffset = 0;
  for (const auto& item : list) {
    m_pData->CopyContentsAt(nOffset, item.span());
    nOffset += item.GetLength();
  }
}

template <typename CharType>
pdfium::span<CharType> StringTemplate<CharType>::GetBuffer(
    size_t nMinBufLength) {
  if (!m_pData) {
    if (nMinBufLength == 0) {
      return pdfium::span<CharType>();
    }
    m_pData = StringData::Create(nMinBufLength);
    m_pData->m_nDataLength = 0;
    m_pData->m_String[0] = 0;
    return pdfium::span<CharType>(m_pData->m_String, m_pData->m_nAllocLength);
  }
  if (m_pData->CanOperateInPlace(nMinBufLength)) {
    return pdfium::span<CharType>(m_pData->m_String, m_pData->m_nAllocLength);
  }
  nMinBufLength = std::max(nMinBufLength, m_pData->m_nDataLength);
  if (nMinBufLength == 0) {
    return pdfium::span<CharType>();
  }
  RetainPtr<StringData> pNewData = StringData::Create(nMinBufLength);
  pNewData->CopyContents(*m_pData);
  pNewData->m_nDataLength = m_pData->m_nDataLength;
  m_pData = std::move(pNewData);
  return pdfium::span<CharType>(m_pData->m_String, m_pData->m_nAllocLength);
}

template <typename CharType>
void StringTemplate<CharType>::ReleaseBuffer(size_t nNewLength) {
  if (!m_pData) {
    return;
  }
  nNewLength = std::min(nNewLength, m_pData->m_nAllocLength);
  if (nNewLength == 0) {
    clear();
    return;
  }
  DCHECK_EQ(m_pData->m_nRefs, 1);
  m_pData->m_nDataLength = nNewLength;
  m_pData->m_String[nNewLength] = 0;
  if (m_pData->m_nAllocLength - nNewLength >= 32) {
    // Over arbitrary threshold, so pay the price to relocate.  Force copy to
    // always occur by holding a second reference to the string.
    StringTemplate preserve(*this);
    ReallocBeforeWrite(nNewLength);
  }
}

template <typename CharType>
size_t StringTemplate<CharType>::Remove(CharType chRemove) {
  if (IsEmpty()) {
    return 0;
  }

  CharType* pstrSource = m_pData->m_String;
  CharType* pstrEnd = m_pData->m_String + m_pData->m_nDataLength;
  while (pstrSource < pstrEnd) {
    if (*pstrSource == chRemove) {
      break;
    }
    pstrSource++;
  }
  if (pstrSource == pstrEnd) {
    return 0;
  }

  ptrdiff_t copied = pstrSource - m_pData->m_String;
  ReallocBeforeWrite(m_pData->m_nDataLength);
  pstrSource = m_pData->m_String + copied;
  pstrEnd = m_pData->m_String + m_pData->m_nDataLength;

  CharType* pstrDest = pstrSource;
  while (pstrSource < pstrEnd) {
    if (*pstrSource != chRemove) {
      *pstrDest = *pstrSource;
      pstrDest++;
    }
    pstrSource++;
  }

  *pstrDest = 0;
  size_t nCount = static_cast<size_t>(pstrSource - pstrDest);
  m_pData->m_nDataLength -= nCount;
  return nCount;
}

template <typename CharType>
void StringTemplate<CharType>::ReallocBeforeWrite(size_t nNewLength) {
  if (m_pData && m_pData->CanOperateInPlace(nNewLength)) {
    return;
  }
  if (nNewLength == 0) {
    clear();
    return;
  }

  RetainPtr<StringData> pNewData = StringData::Create(nNewLength);
  if (m_pData) {
    size_t nCopyLength = std::min(m_pData->m_nDataLength, nNewLength);
    pNewData->CopyContents({m_pData->m_String, nCopyLength});
    pNewData->m_nDataLength = nCopyLength;
  } else {
    pNewData->m_nDataLength = 0;
  }
  pNewData->m_String[pNewData->m_nDataLength] = 0;
  m_pData = std::move(pNewData);
}

template <typename CharType>
void StringTemplate<CharType>::AllocBeforeWrite(size_t nNewLength) {
  if (m_pData && m_pData->CanOperateInPlace(nNewLength)) {
    return;
  }
  if (nNewLength == 0) {
    clear();
    return;
  }
  m_pData = StringData::Create(nNewLength);
}

template <typename CharType>
void StringTemplate<CharType>::AssignCopy(const CharType* pSrcData,
                                          size_t nSrcLen) {
  AllocBeforeWrite(nSrcLen);
  m_pData->CopyContents({pSrcData, nSrcLen});
  m_pData->m_nDataLength = nSrcLen;
}

template <typename CharType>
void StringTemplate<CharType>::Concat(const CharType* pSrcData,
                                      size_t nSrcLen) {
  if (!pSrcData || nSrcLen == 0) {
    return;
  }

  if (!m_pData) {
    m_pData = StringData::Create({pSrcData, nSrcLen});
    return;
  }

  if (m_pData->CanOperateInPlace(m_pData->m_nDataLength + nSrcLen)) {
    m_pData->CopyContentsAt(m_pData->m_nDataLength, {pSrcData, nSrcLen});
    m_pData->m_nDataLength += nSrcLen;
    return;
  }

  size_t nConcatLen = std::max(m_pData->m_nDataLength / 2, nSrcLen);
  RetainPtr<StringData> pNewData =
      StringData::Create(m_pData->m_nDataLength + nConcatLen);
  pNewData->CopyContents(*m_pData);
  pNewData->CopyContentsAt(m_pData->m_nDataLength, {pSrcData, nSrcLen});
  pNewData->m_nDataLength = m_pData->m_nDataLength + nSrcLen;
  m_pData = std::move(pNewData);
}

template <typename CharType>
void StringTemplate<CharType>::clear() {
  if (m_pData && m_pData->CanOperateInPlace(0)) {
    m_pData->m_nDataLength = 0;
    return;
  }
  m_pData.Reset();
}

// static
template <typename CharType>
RetainPtr<typename StringTemplate<CharType>::StringData>
StringTemplate<CharType>::StringData::Create(size_t nLen) {
  DCHECK_GT(nLen, 0u);

  // Calculate space needed for the fixed portion of the struct plus the
  // NUL char that is not included in |m_nAllocLength|.
  int overhead =
      offsetof(StringTemplate::StringData, m_String) + sizeof(CharType);
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
  return pdfium::WrapRetain(new (pData)
                                StringTemplate::StringData(nLen, usableLen));
}

// static
template <typename CharType>
RetainPtr<typename StringTemplate<CharType>::StringData>
StringTemplate<CharType>::StringData::Create(pdfium::span<const CharType> str) {
  RetainPtr<StringTemplate::StringData> result = Create(str.size());
  result->CopyContents(str);
  return result;
}

template <typename CharType>
void StringTemplate<CharType>::StringData::Release() {
  if (--m_nRefs <= 0) {
    FX_StringFree(this);
  }
}

template <typename CharType>
void StringTemplate<CharType>::StringData::CopyContents(
    const StringTemplate::StringData& other) {
  DCHECK(other.m_nDataLength <= m_nAllocLength);
  memcpy(m_String, other.m_String,
         (other.m_nDataLength + 1) * sizeof(CharType));
}

template <typename CharType>
void StringTemplate<CharType>::StringData::CopyContents(
    pdfium::span<const CharType> str) {
  FXSYS_memcpy(m_String, str.data(), str.size_bytes());
  m_String[str.size()] = 0;
}

template <typename CharType>
void StringTemplate<CharType>::StringData::CopyContentsAt(
    size_t offset,
    pdfium::span<const CharType> str) {
  FXSYS_memcpy(m_String + offset, str.data(), str.size_bytes());
  m_String[offset + str.size()] = 0;
}

template <typename CharType>
StringTemplate<CharType>::StringData::StringData(size_t dataLen,
                                                 size_t allocLen)
    : m_nDataLength(dataLen), m_nAllocLength(allocLen) {
  DCHECK_LE(dataLen, allocLen);
  m_String[dataLen] = 0;
}

// Instantiate.
template class StringTemplate<char>;
template class StringTemplate<wchar_t>;

}  // namespace fxcrt
