// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is base::span<> taken from chromium, but modified to be more
// useful for the PDFium environment.

#ifndef CORE_FXCRT_UNOWNED_SPAN_H_
#define CORE_FXCRT_UNOWNED_SPAN_H_

#include <stddef.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <type_traits>
#include <utility>

#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/logging.h"

namespace fxcrt {

template <typename T>
class UnownedSpan;

namespace internal {

template <typename T>
struct IsSpanImpl : std::false_type {};

template <typename T>
struct IsSpanImpl<UnownedSpan<T>> : std::true_type {};

template <typename T>
using IsSpan = IsSpanImpl<typename std::decay<T>::type>;

template <typename T>
struct IsStdArrayImpl : std::false_type {};

template <typename T, size_t N>
struct IsStdArrayImpl<std::array<T, N>> : std::true_type {};

template <typename T>
using IsStdArray = IsStdArrayImpl<typename std::decay<T>::type>;

template <typename From, typename To>
using IsLegalSpanConversion = std::is_convertible<From*, To*>;

template <typename Container, typename T>
using ContainerHasConvertibleData =
    IsLegalSpanConversion<typename std::remove_pointer<decltype(
                              std::declval<Container>().data())>::type,
                          T>;
template <typename Container>
using ContainerHasIntegralSize =
    std::is_integral<decltype(std::declval<Container>().size())>;

template <typename From, typename To>
using EnableIfLegalSpanConversion =
    typename std::enable_if<IsLegalSpanConversion<From, To>::value>::type;

// SFINAE check if Container can be converted to a span<T>. Note that the
// implementation details of this check differ slightly from the requirements in
// the working group proposal: in particular, the proposal also requires that
// the container conversion constructor participate in overload resolution only
// if two additional conditions are true:
//
//   1. Container implements operator[].
//   2. Container::value_type matches remove_const_t<element_type>.
//
// The requirements are relaxed slightly here: in particular, not requiring (2)
// means that an immutable span can be easily constructed from a mutable
// container.
template <typename Container, typename T>
using EnableIfSpanCompatibleContainer =
    typename std::enable_if<!internal::IsSpan<Container>::value &&
                            !internal::IsStdArray<Container>::value &&
                            ContainerHasConvertibleData<Container, T>::value &&
                            ContainerHasIntegralSize<Container>::value>::type;

template <typename Container, typename T>
using EnableIfConstSpanCompatibleContainer =
    typename std::enable_if<std::is_const<T>::value &&
                            !internal::IsSpan<Container>::value &&
                            !internal::IsStdArray<Container>::value &&
                            ContainerHasConvertibleData<Container, T>::value &&
                            ContainerHasIntegralSize<Container>::value>::type;

}  // namespace internal

// A span is a value type that represents an array of elements of type T. Since
// it only consists of a pointer to memory with an associated size, it is very
// light-weight. It is cheap to construct, copy, move and use spans, so that
// users are encouraged to use it as a pass-by-value parameter. A span does not
// own the underlying memory, so care must be taken to ensure that a span does
// not outlive the backing store.
//
// span is somewhat analogous to StringPiece, but with arbitrary element types,
// allowing mutation if T is non-const.
//
// span is implicitly convertible from C++ arrays, as well as most [1]
// container-like types that provide a data() and size() method (such as
// std::vector<T>). A mutable span<T> can also be implicitly converted to an
// immutable span<const T>.
//
// Consider using a span for functions that take a data pointer and size
// parameter: it allows the function to still act on an array-like type, while
// allowing the caller code to be a bit more concise.
//
// For read-only data access pass a span<const T>: the caller can supply either
// a span<const T> or a span<T>, while the callee will have a read-only view.
// For read-write access a mutable span<T> is required.
//
// Without span:
//   Read-Only:
//     // std::string HexEncode(const uint8_t* data, size_t size);
//     std::vector<uint8_t> data_buffer = GenerateData();
//     std::string r = HexEncode(data_buffer.data(), data_buffer.size());
//
//  Mutable:
//     // ssize_t SafeSNPrintf(char* buf, size_t N, const char* fmt, Args...);
//     char str_buffer[100];
//     SafeSNPrintf(str_buffer, sizeof(str_buffer), "Pi ~= %lf", 3.14);
//
// With span:
//   Read-Only:
//     // std::string HexEncode(base::span<const uint8_t> data);
//     std::vector<uint8_t> data_buffer = GenerateData();
//     std::string r = HexEncode(data_buffer);
//
//  Mutable:
//     // ssize_t SafeSNPrintf(base::span<char>, const char* fmt, Args...);
//     char str_buffer[100];
//     SafeSNPrintf(str_buffer, "Pi ~= %lf", 3.14);
//
// Spans with "const" and pointers
// -------------------------------
//
// Const and pointers can get confusing. Here are vectors of pointers and their
// corresponding spans (you can always make the span "more const" too):
//
//   const std::vector<int*>        =>  base::span<int* const>
//   std::vector<const int*>        =>  base::span<const int*>
//   const std::vector<const int*>  =>  base::span<const int* const>
//
// Differences from the working group proposal
// -------------------------------------------
//
// https://wg21.link/P0122 is the latest working group proposal, Chromium
// currently implements R6. The biggest difference is span does not support a
// static extent template parameter. Other differences are documented in
// subsections below.
//
// Differences from [views.constants]:
// - no dynamic_extent constant
//
// Differences from [span.objectrep]:
// - no as_bytes()
// - no as_writeable_bytes()
//
// Differences in constants and types:
// - no element_type type alias
// - no index_type type alias
// - no different_type type alias
// - no extent constant
//
// Differences from [span.cons]:
// - no constructor from a pointer range
// - no constructor from std::array
//
// Differences from [span.sub]:
// - no templated first()
// - no templated last()
// - no templated subspan()
// - using size_t instead of ptrdiff_t for indexing
//
// Differences from [span.obs]:
// - no size_bytes()
// - using size_t instead of ptrdiff_t to represent size()
//
// Differences from [span.elem]:
// - no operator ()()
// - using size_t instead of ptrdiff_t for indexing

// [span], class template span
template <typename T>
class UnownedSpan {
 public:
  using value_type = typename std::remove_cv<T>::type;
  using pointer = T*;
  using reference = T&;
  using iterator = T*;
  using const_iterator = const T*;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  // [span.cons], span constructors, copy, assignment, and destructor
  constexpr UnownedSpan() noexcept : data_(nullptr), size_(0) {}
  constexpr UnownedSpan(T* data, size_t size) noexcept
      : data_(data), size_(size) {}

  template <size_t N>
  constexpr UnownedSpan(T (&array)[N]) noexcept  // NOLINT(runtime/explicit)
      : UnownedSpan(array, N) {}

  // Conversion from a container that provides |T* data()| and |integral_type
  // size()|.
  template <typename Container,
            typename = internal::EnableIfSpanCompatibleContainer<Container, T>>
  constexpr UnownedSpan(Container& container)  // NOLINT(runtime/explicit)
      : UnownedSpan(container.data(), container.size()) {}

  template <
      typename Container,
      typename = internal::EnableIfConstSpanCompatibleContainer<Container, T>>
  UnownedSpan(const Container& container)  // NOLINT(runtime/explicit)
      : UnownedSpan(container.data(), container.size()) {}

  constexpr UnownedSpan(const UnownedSpan& other) noexcept = default;

  // Conversions from spans of compatible types: this allows a span<T> to be
  // seamlessly used as a span<const T>, but not the other way around.
  template <typename U, typename = internal::EnableIfLegalSpanConversion<U, T>>
  constexpr UnownedSpan(const UnownedSpan<U>& other)
      : UnownedSpan(other.data(), other.size()) {}

  // TODO(dcheng): Implement construction from a |begin| and |end| pointer.
  // TODO(dcheng): Implement construction from std::array.

  UnownedSpan& operator=(const UnownedSpan& other) noexcept = default;
  ~UnownedSpan() noexcept = default;

  // [span.sub], span subviews
  UnownedSpan first(size_t count) const {
    CHECK(count <= size_);
    return UnownedSpan(data_, count);
  }

  UnownedSpan last(size_t count) const {
    CHECK(count <= size_);
    return UnownedSpan(data_.Get() + (size_ - count), count);
  }

  UnownedSpan subspan(size_t pos, size_t count = -1) const {
    const auto npos = static_cast<size_t>(-1);
    CHECK(pos <= size_);
    CHECK(count == npos || count <= size_ - pos);
    return UnownedSpan(data_.Get() + pos, count == npos ? size_ - pos : count);
  }

  // [span.obs], span observers
  constexpr size_t size() const noexcept { return size_; }
  constexpr bool empty() const noexcept { return size_ == 0; }

  // bool conversion is a PDFium extension.
  explicit operator bool() const noexcept { return !empty(); }

  // [span.elem], span element access
  // Non-const span element access is a PDFium extension.
  T& operator[](size_t index) const noexcept {
    CHECK(index < size_);
    return data_.Get()[index];
  }
  T* data() const noexcept { return data_.Get(); }

  // Checked dereference is a PDFium extension.
  T& operator*() const noexcept {
    CHECK(size_);
    return *data_;
  }

  // Increment operations are a PDFium extension
  UnownedSpan operator+(size_t count) {
    CHECK(count <= size_);
    return count == size_ ? UnownedSpan()
                          : UnownedSpan(data_.Get() + count, size_ - count);
  }
  UnownedSpan operator+=(size_t count) {
    *this = *this + count;
    return *this;
  }
  UnownedSpan& operator++() {
    // Pre-increment as indicated by lack of dummy arg.
    *this += 1;
    return *this;
  }
  UnownedSpan<T> operator++(int) {
    UnownedSpan that = *this;
    *this += 1;
    return that;
  }

  // [span.iter], span iterator support
  // Non-const iterator access is a PDFium extension.
  iterator begin() noexcept { return data_.Get(); }
  iterator end() noexcept { return data_.Get() + size_; }

  const_iterator begin() const noexcept { return data_.Get(); }
  const_iterator end() const noexcept { return data_.Get() + size_; }

  reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
  reverse_iterator rend() noexcept { return reverse_iterator(begin()); }

  const_reverse_iterator rbegin() const noexcept {
    return const_reverse_iterator(end());
  }
  const_reverse_iterator rend() const noexcept {
    return const_reverse_iterator(begin());
  }

 private:
  UnownedPtr<T> data_;
  size_t size_;
};

// [span.comparison], span comparison operators
// Relational operators. Equality is a element-wise comparison.
template <typename T>
constexpr bool operator==(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return lhs.size() == rhs.size() &&
         std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

template <typename T>
constexpr bool operator!=(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return !(lhs == rhs);
}

template <typename T>
constexpr bool operator<(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return std::lexicographical_compare(lhs.cbegin(), lhs.cend(), rhs.cbegin(),
                                      rhs.cend());
}

template <typename T>
constexpr bool operator<=(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return !(rhs < lhs);
}

template <typename T>
constexpr bool operator>(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return rhs < lhs;
}

template <typename T>
constexpr bool operator>=(UnownedSpan<T> lhs, UnownedSpan<T> rhs) noexcept {
  return !(lhs < rhs);
}

}  // namespace fxcrt

using fxcrt::UnownedSpan;

namespace pdfium {

// Type-deducing helpers for constructing a UnownedSpan.
template <typename T>
constexpr UnownedSpan<T> MakeUnownedSpan(T* data, size_t size) noexcept {
  return UnownedSpan<T>(data, size);
}

template <typename T, size_t N>
constexpr UnownedSpan<T> MakeUnownedSpan(T (&array)[N]) noexcept {
  return UnownedSpan<T>(array);
}

template <
    typename Container,
    typename T = typename Container::value_type,
    typename = fxcrt::internal::EnableIfSpanCompatibleContainer<Container, T>>
constexpr UnownedSpan<T> MakeUnownedSpan(Container& container) {
  return UnownedSpan<T>(container);
}

template <
    typename Container,
    typename T = typename std::add_const<typename Container::value_type>::type,
    typename =
        fxcrt::internal::EnableIfConstSpanCompatibleContainer<Container, T>>
constexpr UnownedSpan<T> MakeUnownedSpan(const Container& container) {
  return UnownedSpan<T>(container);
}

}  // namespace pdfium

#endif  // CORE_FXCRT_UNOWNED_SPAN_H_
