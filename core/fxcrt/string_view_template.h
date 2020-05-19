// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_STRING_VIEW_TEMPLATE_H_
#define CORE_FXCRT_STRING_VIEW_TEMPLATE_H_

#include <algorithm>
#include <iterator>
#include <type_traits>
#include <vector>

#include "core/fxcrt/fx_system.h"
#include "third_party/base/optional.h"
#include "third_party/base/span.h"

namespace fxcrt {

// An immutable string with caller-provided storage which must outlive the
// string itself. These are not necessarily nul-terminated, so that substring
// extraction (via the Substr(), First(), and Last() methods) is copy-free.
//
// String view arguments should be passed by value, since they are small,
// rather than const-ref, even if they are not modified.
template <typename T>
class StringViewTemplate {
 public:
  using CharType = T;
  using UnsignedType = typename std::make_unsigned<CharType>::type;
  using const_iterator = const CharType*;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  constexpr StringViewTemplate() noexcept = default;
  constexpr StringViewTemplate(const StringViewTemplate& src) noexcept =
      default;

  // Deliberately implicit to avoid calling on every string literal.
  // NOLINTNEXTLINE(runtime/explicit)
  StringViewTemplate(const CharType* ptr) noexcept
      : span_(reinterpret_cast<const UnsignedType*>(ptr),
              ptr ? FXSYS_len(ptr) : 0) {}

  constexpr StringViewTemplate(const CharType* ptr, size_t len) noexcept
      : span_(reinterpret_cast<const UnsignedType*>(ptr), len) {}

  explicit constexpr StringViewTemplate(
      const pdfium::span<const CharType>& other) noexcept
      : span_(reinterpret_cast<const UnsignedType*>(other.data()),
              other.size()) {}

  template <typename U = UnsignedType>
  constexpr StringViewTemplate(
      const UnsignedType* ptr,
      size_t size,
      typename std::enable_if<!std::is_same<U, CharType>::value>::type* =
          0) noexcept
      : span_(ptr, size) {}

  template <typename U = UnsignedType>
  StringViewTemplate(
      const pdfium::span<U> other,
      typename std::enable_if<!std::is_same<U, CharType>::value>::type* =
          0) noexcept
      : span_(other) {}

  // Deliberately implicit to avoid calling on every string literal.
  // |ch| must be an lvalue that outlives the StringViewTemplate.
  // NOLINTNEXTLINE(runtime/explicit)
  constexpr StringViewTemplate(CharType& ch) noexcept
      : span_(reinterpret_cast<const UnsignedType*>(&ch), 1) {}

  // Any changes to |vec| invalidate the string.
  template <typename AllocType>
  explicit StringViewTemplate(
      const std::vector<UnsignedType, AllocType>& vec) noexcept
      : span_(!vec.empty() ? vec.data() : nullptr, vec.size()) {}

  StringViewTemplate& operator=(const CharType* src) {
    span_ = pdfium::span<const UnsignedType>(
        reinterpret_cast<const UnsignedType*>(src), src ? FXSYS_len(src) : 0);
    return *this;
  }

  StringViewTemplate& operator=(const StringViewTemplate& src) {
    span_ = src.span_;
    return *this;
  }

  const_iterator begin() const {
    return reinterpret_cast<const_iterator>(span_.begin());
  }
  const_iterator end() const {
    return reinterpret_cast<const_iterator>(span_.end());
  }
  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(end());
  }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(begin());
  }

  bool operator==(const StringViewTemplate& other) const {
    return span_ == other.span_;
  }
  bool operator==(const CharType* ptr) const {
    StringViewTemplate other(ptr);
    return *this == other;
  }
  bool operator!=(const CharType* ptr) const { return !(*this == ptr); }
  bool operator!=(const StringViewTemplate& other) const {
    return !(*this == other);
  }

  bool IsASCII() const {
    for (auto c : *this) {
      if (c <= 0 || c > 127)  // Questionable signedness of |c|.
        return false;
    }
    return true;
  }

  bool EqualsASCII(const StringViewTemplate<char>& that) const {
    size_t length = GetLength();
    if (length != that.GetLength())
      return false;

    for (size_t i = 0; i < length; ++i) {
      auto c = (*this)[i];
      if (c <= 0 || c > 127 || c != that[i])  // Questionable signedness of |c|.
        return false;
    }
    return true;
  }

  bool EqualsASCIINoCase(const StringViewTemplate<char>& that) const {
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
    if (span_.empty())
      return 0;

    uint32_t strid = 0;
    size_t size = std::min(static_cast<size_t>(4), span_.size());
    for (size_t i = 0; i < size; i++)
      strid = strid * 256 + span_[i];

    return strid << ((4 - size) * 8);
  }

  pdfium::span<const UnsignedType> raw_span() const { return span_; }
  pdfium::span<const CharType> span() const {
    return pdfium::make_span(reinterpret_cast<const CharType*>(span_.data()),
                             span_.size());
  }
  const UnsignedType* raw_str() const { return span_.data(); }
  const CharType* unterminated_c_str() const {
    return reinterpret_cast<const CharType*>(span_.data());
  }

  size_t GetLength() const { return span_.size(); }
  bool IsEmpty() const { return span_.empty(); }
  bool IsValidIndex(size_t index) const { return index < span_.size(); }
  bool IsValidLength(size_t length) const { return length <= span_.size(); }

  const UnsignedType& operator[](const size_t index) const {
    return span_[index];
  }

  UnsignedType Front() const { return !span_.empty() ? span_[0] : 0; }
  UnsignedType Back() const {
    return !span_.empty() ? span_[span_.size() - 1] : 0;
  }

  const CharType CharAt(const size_t index) const {
    return static_cast<CharType>(span_[index]);
  }

  Optional<size_t> Find(CharType ch) const {
    const auto* found = reinterpret_cast<const UnsignedType*>(FXSYS_chr(
        reinterpret_cast<const CharType*>(span_.data()), ch, span_.size()));

    return found ? Optional<size_t>(found - span_.data()) : Optional<size_t>();
  }

  bool Contains(CharType ch) const { return Find(ch).has_value(); }

  StringViewTemplate Substr(size_t first, size_t count) const {
    if (!span_.data())
      return StringViewTemplate();

    if (!IsValidIndex(first))
      return StringViewTemplate();

    if (count == 0 || !IsValidLength(count))
      return StringViewTemplate();

    if (!IsValidIndex(first + count - 1))
      return StringViewTemplate();

    return StringViewTemplate(span_.data() + first, count);
  }

  StringViewTemplate First(size_t count) const {
    if (count == 0 || !IsValidLength(count))
      return StringViewTemplate();
    return Substr(0, count);
  }

  StringViewTemplate Last(size_t count) const {
    if (count == 0 || !IsValidLength(count))
      return StringViewTemplate();
    return Substr(GetLength() - count, count);
  }

  StringViewTemplate TrimmedRight(CharType ch) const {
    if (IsEmpty())
      return StringViewTemplate();

    size_t pos = GetLength();
    while (pos && CharAt(pos - 1) == ch)
      pos--;

    if (pos == 0)
      return StringViewTemplate();

    return StringViewTemplate(span_.data(), pos);
  }

  bool operator<(const StringViewTemplate& that) const {
    int result = FXSYS_cmp(reinterpret_cast<const CharType*>(span_.data()),
                           reinterpret_cast<const CharType*>(that.span_.data()),
                           std::min(span_.size(), that.span_.size()));
    return result < 0 || (result == 0 && span_.size() < that.span_.size());
  }

  bool operator>(const StringViewTemplate& that) const {
    int result = FXSYS_cmp(reinterpret_cast<const CharType*>(span_.data()),
                           reinterpret_cast<const CharType*>(that.span_.data()),
                           std::min(span_.size(), that.span_.size()));
    return result > 0 || (result == 0 && span_.size() > that.span_.size());
  }

 protected:
  pdfium::span<const UnsignedType> span_;

 private:
  void* operator new(size_t) throw() { return nullptr; }
};

template <typename T>
inline bool operator==(const T* lhs, const StringViewTemplate<T>& rhs) {
  return rhs == lhs;
}
template <typename T>
inline bool operator!=(const T* lhs, const StringViewTemplate<T>& rhs) {
  return rhs != lhs;
}
template <typename T>
inline bool operator<(const T* lhs, const StringViewTemplate<T>& rhs) {
  return rhs > lhs;
}

// Workaround for one of the cases external template classes are
// failing in GCC before version 7 with -O0
#if !defined(__GNUC__) || __GNUC__ >= 7
extern template class StringViewTemplate<char>;
extern template class StringViewTemplate<wchar_t>;
#endif

using ByteStringView = StringViewTemplate<char>;
using WideStringView = StringViewTemplate<wchar_t>;

}  // namespace fxcrt

using ByteStringView = fxcrt::ByteStringView;
using WideStringView = fxcrt::WideStringView;

#endif  // CORE_FXCRT_STRING_VIEW_TEMPLATE_H_
