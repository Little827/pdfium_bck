// Copyright 2016 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_STRING_VIEW_TEMPLATE_H_
#define CORE_FXCRT_STRING_VIEW_TEMPLATE_H_

#include <ctype.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <utility>

#include "core/fxcrt/fx_memcpy_wrappers.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/span.h"
#include "core/fxcrt/span_util.h"

namespace fxcrt {

// An immutable string with caller-provided storage which must outlive the
// string itself. These are not necessarily nul-terminated, so that substring
// extraction (via the Substr(), First(), and Last() methods) is copy-free.
//
// String view arguments should be passed by value, since they are small,
// rather than const-ref, even if they are not modified.
//
// Front() and Back() tolerate empty strings and must return NUL in those
// cases. Substr(), First(), and Last() tolerate out-of-range indices and
// must return an empty string view in those cases. The aim here is allowing
// callers to avoid range-checking first.
template <typename T, bool HasNulTerm = false>
class StringViewTemplate {
 public:
  using CharType = T;
  using UnsignedType = typename std::make_unsigned<CharType>::type;
  using const_iterator = const CharType*;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  template <typename OtherType, bool OtherHasNulTerm>
  friend class StringViewTemplate;

  // Escape hatch when creating from other string classes (not for you to use).
  enum ExceptFlag { kIPromiseThisIsNulTerminated };

  constexpr StringViewTemplate() noexcept = default;

  template <bool OtherHasNulTerm>
  constexpr StringViewTemplate(
      const StringViewTemplate<CharType, OtherHasNulTerm>& other) noexcept
    requires(!HasNulTerm || OtherHasNulTerm)
      : m_Span(other.m_Span) {}

  template <bool OtherHasNulTerm>
  constexpr StringViewTemplate(
      StringViewTemplate<CharType, OtherHasNulTerm>&& other) noexcept
    requires(!HasNulTerm || OtherHasNulTerm)
      : m_Span(std::move(other.m_Span)) {}

  // Deliberately implicit to avoid calling on every string literal.
  // NOLINTNEXTLINE(runtime/explicit)
  StringViewTemplate(const CharType* ptr) noexcept
      : m_Span(reinterpret_cast<const UnsignedType*>(ptr),
               ptr ? FXSYS_len(ptr) : 0) {}

  constexpr StringViewTemplate(const CharType* ptr, size_t size) noexcept
    requires(!HasNulTerm)
      : m_Span(reinterpret_cast<const UnsignedType*>(ptr), size) {}

  constexpr StringViewTemplate(const UnsignedType* ptr, size_t size) noexcept
    requires(!HasNulTerm && !std::is_same<UnsignedType, CharType>::value)
      : m_Span(ptr, size) {}

  // Overrides for when the caller knows there is a NULL at ptr[size].
  constexpr StringViewTemplate(const CharType* ptr,
                               size_t size,
                               ExceptFlag flag) noexcept
      : m_Span(reinterpret_cast<const UnsignedType*>(ptr), size) {}

  constexpr StringViewTemplate(const UnsignedType* ptr,
                               size_t size,
                               ExceptFlag flag) noexcept
    requires(HasNulTerm && !std::is_same<UnsignedType, CharType>::value)
      : m_Span(ptr, size) {}

  explicit constexpr StringViewTemplate(
      const pdfium::span<const CharType>& other) noexcept
    requires(!HasNulTerm)
      : m_Span(!other.empty()
                   ? reinterpret_cast<const UnsignedType*>(other.data())
                   : nullptr,
               other.size()) {}

  constexpr StringViewTemplate(
      const pdfium::span<const UnsignedType>& other) noexcept
    requires(!HasNulTerm && !std::is_same<UnsignedType, CharType>::value)
      : m_Span(!other.empty() ? other.data() : nullptr, other.size()) {}

  // Deliberately implicit to avoid calling on every char literal.
  // |ch| must be an lvalue that outlives the StringViewTemplate.
  // NOLINTNEXTLINE(runtime/explicit)
  constexpr StringViewTemplate(const CharType& ch) noexcept
    requires(!HasNulTerm)
      : m_Span(reinterpret_cast<const UnsignedType*>(&ch), 1u) {}

  StringViewTemplate& operator=(const CharType* src) {
    m_Span = pdfium::span<const UnsignedType>(
        reinterpret_cast<const UnsignedType*>(src), src ? FXSYS_len(src) : 0);
    return *this;
  }

  template <bool OtherHasNulTerm>
  StringViewTemplate& operator=(
      const StringViewTemplate<CharType, OtherHasNulTerm>& src)
    requires(!HasNulTerm || OtherHasNulTerm)
  {
    m_Span = src.m_Span;
    return *this;
  }

  const_iterator begin() const {
    return reinterpret_cast<const_iterator>(m_Span.begin());
  }
  const_iterator end() const {
    return reinterpret_cast<const_iterator>(m_Span.end());
  }
  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(end());
  }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(begin());
  }

  template <bool OtherHasNulTerm>
  bool operator==(
      const StringViewTemplate<CharType, OtherHasNulTerm>& other) const {
    return std::equal(m_Span.begin(), m_Span.end(), other.m_Span.begin(),
                      other.m_Span.end());
  }
  bool operator==(const CharType* ptr) const {
    StringViewTemplate other(ptr);
    return *this == other;
  }
  template <bool OtherHasNulTerm>
  bool operator!=(
      const StringViewTemplate<CharType, OtherHasNulTerm>& other) const {
    return !(*this == other);
  }
  bool operator!=(const CharType* ptr) const { return !(*this == ptr); }

  bool IsASCII() const {
    for (auto c : *this) {
      if (c <= 0 || c > 127)  // Questionable signedness of |c|.
        return false;
    }
    return true;
  }

  bool EqualsASCII(const StringViewTemplate<char, false>& that) const {
    size_t length = GetLength();
    if (length != that.GetLength()) {
      return false;
    }
    for (size_t i = 0; i < length; ++i) {
      auto c = (*this)[i];
      if (c <= 0 || c > 127 || c != that[i])  // Questionable signedness of |c|.
        return false;
    }
    return true;
  }

  bool EqualsASCIINoCase(const StringViewTemplate<char, false>& that) const {
    size_t length = GetLength();
    if (length != that.GetLength())
      return false;

    for (size_t i = 0; i < length; ++i) {
      auto c = (*this)[i];
      if (c <= 0 || c > 127 || tolower(c) != tolower(that[i]))
        return false;
    }
    return true;
  }

  uint32_t GetID() const {
    if (m_Span.empty())
      return 0;

    uint32_t strid = 0;
    size_t size = std::min(static_cast<size_t>(4), m_Span.size());
    for (size_t i = 0; i < size; i++)
      strid = strid * 256 + m_Span[i];

    return strid << ((4 - size) * 8);
  }

  pdfium::span<const UnsignedType> unsigned_span() const { return m_Span; }
  pdfium::span<const CharType> span() const {
    return pdfium::make_span(reinterpret_cast<const CharType*>(m_Span.data()),
                             m_Span.size());
  }

  const UnsignedType* unsigned_str() const
    requires(HasNulTerm)
  {
    return m_Span.data();
  }
  const CharType* c_str() const
    requires(HasNulTerm)
  {
    return reinterpret_cast<const CharType*>(m_Span.data());
  }

  const UnsignedType* unterminated_unsigned_str() const
    requires(!HasNulTerm)
  {
    return m_Span.data();
  }
  const CharType* unterminated_c_str() const
    requires(!HasNulTerm)
  {
    return reinterpret_cast<const CharType*>(m_Span.data());
  }

  size_t GetLength() const { return m_Span.size(); }
  bool IsEmpty() const { return m_Span.empty(); }
  bool IsValidIndex(size_t index) const { return index < m_Span.size(); }
  bool IsValidLength(size_t length) const { return length <= m_Span.size(); }

  // CHECK() if index is out of range (via span's operator[]).
  const UnsignedType& operator[](const size_t index) const {
    return m_Span[index];
  }

  // CHECK() if index is out of range (via span's operator[]).
  CharType CharAt(const size_t index) const {
    return static_cast<CharType>(m_Span[index]);
  }

  // Unlike std::string_view::front(), this is always safe and returns a
  // NUL char when the string is empty.
  UnsignedType Front() const { return !m_Span.empty() ? m_Span.front() : 0; }

  // Unlike std::string_view::back(), this is always safe and returns a
  // NUL char when the string is empty.
  UnsignedType Back() const { return !m_Span.empty() ? m_Span.back() : 0; }

  std::optional<size_t> Find(CharType ch) const {
    const auto* found = reinterpret_cast<const UnsignedType*>(FXSYS_chr(
        reinterpret_cast<const CharType*>(m_Span.data()), ch, m_Span.size()));

    return found ? std::optional<size_t>(found - m_Span.data()) : std::nullopt;
  }

  bool Contains(CharType ch) const { return Find(ch).has_value(); }

  // NOTE: The end of a NUL terminated StringView is NUL terminated.
  StringViewTemplate<CharType, HasNulTerm> Substr(size_t offset) const {
    if (!m_Span.data()) {
      return StringViewTemplate<CharType, HasNulTerm>();
    }
    if (!IsValidIndex(offset)) {
      return StringViewTemplate<CharType, HasNulTerm>();
    }
    // NOTE: Can't construct direclty from subspan() since that is only allowed
    // for the non-NUL terminated case.
    auto span = reinterpret_span<const CharType>(m_Span.subspan(offset));
    return StringViewTemplate<CharType, HasNulTerm>(
        span.data(), span.size(), kIPromiseThisIsNulTerminated);
  }

  // NOTE: The middle of a NUL terminated StringView is not NUL terminated.
  StringViewTemplate<CharType, false> Substr(size_t offset,
                                             size_t count) const {
    if (!m_Span.data()) {
      return StringViewTemplate<CharType, false>();
    }
    if (!IsValidIndex(offset)) {
      return StringViewTemplate<CharType, false>();
    }
    if (count == 0 || !IsValidLength(count)) {
      return StringViewTemplate<CharType, false>();
    }
    if (!IsValidIndex(offset + count - 1)) {
      return StringViewTemplate<CharType, false>();
    }
    return StringViewTemplate<CharType, false>(m_Span.subspan(offset, count));
  }

  // NOTE: The start of a NUL terminated StringView is not NUL terminated.
  StringViewTemplate<CharType, false> First(size_t count) const {
    return Substr(0, count);
  }

  // NOTE: The end of a NUL terminated StringView is NUL terminated.
  StringViewTemplate<CharType, HasNulTerm> Last(size_t count) const {
    // Unsigned underflow is well-defined and out-of-range is handled by
    // Substr().
    return Substr(GetLength() - count);
  }

  // NOTE: The start of a NUL terminated StringView is not NUL terminated.
  // TODO(tsepez): rename this to TrimmedBack().
  StringViewTemplate<CharType, false> TrimmedRight(CharType ch) const {
    if (IsEmpty()) {
      return StringViewTemplate<CharType, false>();
    }
    size_t pos = GetLength();
    while (pos && CharAt(pos - 1) == ch) {
      pos--;
    }
    // Not strictly needed, but may avoid dangling ptrs.
    if (pos == 0) {
      return StringViewTemplate<CharType, false>();
    }
    return StringViewTemplate<CharType, false>(m_Span.data(), pos);
  }

  bool operator<(const StringViewTemplate<CharType, false>& that) const {
    int result =
        FXSYS_cmp(reinterpret_cast<const CharType*>(m_Span.data()),
                  reinterpret_cast<const CharType*>(that.m_Span.data()),
                  std::min(m_Span.size(), that.m_Span.size()));
    return result < 0 || (result == 0 && m_Span.size() < that.m_Span.size());
  }

  bool operator>(const StringViewTemplate<CharType, false>& that) const {
    int result =
        FXSYS_cmp(reinterpret_cast<const CharType*>(m_Span.data()),
                  reinterpret_cast<const CharType*>(that.m_Span.data()),
                  std::min(m_Span.size(), that.m_Span.size()));
    return result > 0 || (result == 0 && m_Span.size() > that.m_Span.size());
  }

 protected:
  // This is not a raw_span<> because StringViewTemplates must be passed by
  // value without introducing BackupRefPtr churn. Also, repeated re-assignment
  // of substrings of a StringViewTemplate to itself must avoid the same issue.
  pdfium::span<const UnsignedType> m_Span;

 private:
  void* operator new(size_t) throw() { return nullptr; }
};

template <typename T, bool B>
inline bool operator==(const T* lhs, const StringViewTemplate<T, B>& rhs) {
  return rhs == lhs;
}
template <typename T, bool B>
inline bool operator!=(const T* lhs, const StringViewTemplate<T, B>& rhs) {
  return rhs != lhs;
}
template <typename T, bool B>
inline bool operator<(const T* lhs, const StringViewTemplate<T, B>& rhs) {
  return rhs > lhs;
}

extern template class StringViewTemplate<char>;
extern template class StringViewTemplate<wchar_t>;

using ByteStringView = StringViewTemplate<char>;
using WideStringView = StringViewTemplate<wchar_t>;

}  // namespace fxcrt

using ByteStringView = fxcrt::ByteStringView;
using WideStringView = fxcrt::WideStringView;

#endif  // CORE_FXCRT_STRING_VIEW_TEMPLATE_H_
