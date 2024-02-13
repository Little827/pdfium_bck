// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_STRING_TEMPLATE_H_
#define CORE_FXCRT_STRING_TEMPLATE_H_

#include <stddef.h>

#include <type_traits>

#include "core/fxcrt/retain_ptr.h"
#include "core/fxcrt/string_view_template.h"

namespace fxcrt {

// Base class for a  mutable string with shared buffers using copy-on-write
// semantics that avoids std::string's iterator stability guarantees.
template <typename T>
class StringTemplate {
 public:
  using CharType = T;
  using UnsignedType = typename std::make_unsigned<CharType>::type;
  using StringView = StringViewTemplate<T>;
  using const_iterator = T*;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  StringTemplate() = default;
  StringTemplate(const StringTemplate& other) = default;

  // Move-construct a StringTemplate. After construction, |other| is empty.
  StringTemplate(StringTemplate&& other) noexcept = default;

  // Make a one-character string from a char.
  explicit StringTemplate(CharType ch);

  StringTemplate(const CharType* pStr, size_t len);
  StringTemplate(const UnsignedType* pStr, size_t len)
    requires(!std::is_same_v<CharType, UnsignedType>)
      : StringTemplate(reinterpret_cast<const CharType*>(pStr), len) {}

  explicit StringTemplate(StringView bstrc);
  StringTemplate(StringView str1, StringView str2);
  StringTemplate(const std::initializer_list<StringView>& list);

  bool IsEmpty() const { return !GetLength(); }
  size_t GetLength() const { return m_pData ? m_pData->m_nDataLength : 0; }

  // Explicit conversion to UnsignedType*. May return nullptr.
  // Note: Any subsequent modification of |this| will invalidate the result.
  const UnsignedType* raw_str() const {
    return m_pData ? reinterpret_cast<const UnsignedType*>(m_pData->m_String)
                   : nullptr;
  }

  // Explicit conversion to ByteStringView.
  // Note: Any subsequent modification of |this| will invalidate the result.
  StringViewTemplate<CharType> AsStringView() const {
    return StringViewTemplate<CharType>(raw_str(), GetLength());
  }

  // Explicit conversion to span.
  // Note: Any subsequent modification of |this| will invalidate the result.
  pdfium::span<const CharType> span() const {
    return pdfium::make_span(m_pData ? m_pData->m_String : nullptr,
                             GetLength());
  }

  // Explicit conversion to spans of unsigned types.
  // Note: Any subsequent modification of |this| will invalidate the result.
  pdfium::span<const UnsignedType> raw_span() const {
    return pdfium::make_span(raw_str(), GetLength());
  }

  // Note: Any subsequent modification of |this| will invalidate iterators.
  const_iterator begin() const {
    return m_pData ? m_pData->span().begin() : nullptr;
  }
  const_iterator end() const {
    return m_pData ? m_pData->span().end() : nullptr;
  }

  // Note: Any subsequent modification of |this| will invalidate iterators.
  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(end());
  }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(begin());
  }

  bool IsValidIndex(size_t index) const { return index < GetLength(); }
  bool IsValidLength(size_t length) const { return length <= GetLength(); }

  // CHECK() if index is out of range (via span's operator[]).
  CharType operator[](const size_t index) const {
    CHECK(m_pData);
    return m_pData->span()[index];
  }

  // Unlike std::wstring::front(), this is always safe and returns a
  // NUL char when the string is empty.
  CharType Front() const { return m_pData ? m_pData->Front() : 0; }

  // Unlike std::wstring::back(), this is always safe and returns a
  // NUL char when the string is empty.
  CharType Back() const { return m_pData ? m_pData->Back() : 0; }

  // Holds on to buffer if possible for later re-use. Use assignment
  // to force immediate release if desired.
  void clear();

  // Increase the backing store of the string so that it is capable of storing
  // at least `nMinBufLength` chars. Returns a span to the entire buffer,
  // which may be larger than `nMinBufLength` due to rounding by allocators.
  // Note: any modification of the string (including ReleaseBuffer()) may
  // invalidate the span, which must not outlive its buffer.
  pdfium::span<T> GetBuffer(size_t nMinBufLength);

  // Sets the size of the string to `nNewLength` chars. Call this after a call
  // to GetBuffer(), to indicate how much of the buffer was actually used.
  void ReleaseBuffer(size_t nNewLength);

  size_t Remove(T ch);

 protected:
  class StringData {
   public:
    static RetainPtr<StringData> Create(size_t nLen);
    static RetainPtr<StringData> Create(pdfium::span<const CharType> str);

    void Retain() { ++m_nRefs; }
    void Release();

    bool CanOperateInPlace(size_t nTotalLen) const {
      return m_nRefs <= 1 && nTotalLen <= m_nAllocLength;
    }

    void CopyContents(const StringData& other);
    void CopyContents(pdfium::span<const CharType> str);
    void CopyContentsAt(size_t offset, pdfium::span<const CharType> str);

    pdfium::span<CharType> span() {
      return pdfium::make_span(m_String, m_nDataLength);
    }
    pdfium::span<const CharType> span() const {
      return pdfium::make_span(m_String, m_nDataLength);
    }

    // Unlike std::string::front(), this is always safe and returns a
    // NUL char when the string is empty.
    CharType Front() const { return !span().empty() ? span().front() : 0; }

    // Unlike std::string::back(), this is always safe and returns a
    // NUL char when the string is empty.
    CharType Back() const { return !span().empty() ? span().back() : 0; }

    // To ensure ref counts do not overflow, consider the worst possible case:
    // the entire address space contains nothing but pointers to this object.
    // Since the count increments with each new pointer, the largest value is
    // the number of pointers that can fit into the address space. The size of
    // the address space itself is a good upper bound on it.
    intptr_t m_nRefs = 0;

    // These lengths are in terms of number of characters, not bytes, and do not
    // include the terminating NUL character, but the underlying buffer is sized
    // to be capable of holding it.
    size_t m_nDataLength;
    const size_t m_nAllocLength;

    // Not really 1, variable size.
    CharType m_String[1];

   private:
    StringData(size_t dataLen, size_t allocLen);
    ~StringData() = delete;
  };

  ~StringTemplate() = default;

  void ReallocBeforeWrite(size_t nNewLen);
  void AllocBeforeWrite(size_t nNewLen);
  void AssignCopy(const T* pSrcData, size_t nSrcLen);
  void Concat(const T* pSrcData, size_t nSrcLen);

  RetainPtr<StringData> m_pData;
};

extern template class StringTemplate<char>;
extern template class StringTemplate<wchar_t>;

}  // namespace fxcrt

#endif  // CORE_FXCRT_STRING_TEMPLATE_H_
