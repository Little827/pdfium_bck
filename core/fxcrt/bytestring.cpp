// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/bytestring.h"

#include <stddef.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>

#include "core/fxcrt/cfx_utf8decoder.h"
#include "core/fxcrt/fx_codepage.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/string_pool_template.h"
#include "third_party/base/numerics/safe_math.h"
#include "third_party/base/span.h"
#include "third_party/base/stl_util.h"

template class fxcrt::StringDataTemplate<char>;
template class fxcrt::StringViewTemplate<char>;
template class fxcrt::StringPoolTemplate<ByteString>;
template struct std::hash<ByteString>;

namespace {

constexpr char kTrimChars[] = "\x09\x0a\x0b\x0c\x0d\x20";

const char* FX_strstr(const char* haystack,
                      int haystack_len,
                      const char* needle,
                      int needle_len) {
  if (needle_len > haystack_len || needle_len == 0) {
    return nullptr;
  }
  const char* end_ptr = haystack + haystack_len - needle_len;
  while (haystack <= end_ptr) {
    int i = 0;
    while (1) {
      if (haystack[i] != needle[i]) {
        break;
      }
      i++;
      if (i == needle_len) {
        return haystack;
      }
    }
    haystack++;
  }
  return nullptr;
}

}  // namespace

namespace fxcrt {

static_assert(sizeof(ByteString) <= sizeof(char*),
              "Strings must not require more space than pointers");

#define FORCE_ANSI 0x10000
#define FORCE_UNICODE 0x20000
#define FORCE_INT64 0x40000

// static
ByteString ByteString::FormatInteger(int i) {
  char buf[32];
  FXSYS_snprintf(buf, sizeof(buf), "%d", i);
  return ByteString(buf);
}

// static
ByteString ByteString::FormatFloat(float f) {
  char buf[32];
  return ByteString(buf, FloatToString(f, buf));
}

// static
ByteString ByteString::FormatV(const char* pFormat, va_list argList) {
  va_list argListCopy;
  va_copy(argListCopy, argList);
  int nMaxLen = vsnprintf(nullptr, 0, pFormat, argListCopy);
  va_end(argListCopy);

  if (nMaxLen <= 0)
    return ByteString();

  ByteString ret;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<char> buf = ret.GetBuffer(nMaxLen);

    // In the following two calls, there's always space in the buffer for
    // a terminating NUL that's not included in nMaxLen.
    memset(buf.data(), 0, nMaxLen + 1);
    va_copy(argListCopy, argList);
    vsnprintf(buf.data(), nMaxLen + 1, pFormat, argListCopy);
    va_end(argListCopy);
  }
  ret.ReleaseBuffer(ret.GetStringLength());
  return ret;
}

// static
ByteString ByteString::Format(const char* pFormat, ...) {
  va_list argList;
  va_start(argList, pFormat);
  ByteString ret = FormatV(pFormat, argList);
  va_end(argList);

  return ret;
}

ByteString::ByteString(const char* pStr, size_t nLen) {
  if (nLen)
    data_.Reset(StringData::Create(pStr, nLen));
}

ByteString::ByteString(const uint8_t* pStr, size_t nLen) {
  if (nLen)
    data_.Reset(StringData::Create(reinterpret_cast<const char*>(pStr), nLen));
}

ByteString::ByteString() = default;

ByteString::ByteString(const ByteString& other) : data_(other.data_) {}

ByteString::ByteString(ByteString&& other) noexcept {
  data_.Swap(other.data_);
}

ByteString::ByteString(char ch) {
  data_.Reset(StringData::Create(1));
  data_->string_[0] = ch;
}

ByteString::ByteString(const char* ptr)
    : ByteString(ptr, ptr ? strlen(ptr) : 0) {}

ByteString::ByteString(ByteStringView bstrc) {
  if (!bstrc.IsEmpty()) {
    data_.Reset(
        StringData::Create(bstrc.unterminated_c_str(), bstrc.GetLength()));
  }
}

ByteString::ByteString(ByteStringView str1, ByteStringView str2) {
  FX_SAFE_SIZE_T nSafeLen = str1.GetLength();
  nSafeLen += str2.GetLength();

  size_t nNewLen = nSafeLen.ValueOrDie();
  if (nNewLen == 0)
    return;

  data_.Reset(StringData::Create(nNewLen));
  data_->CopyContents(str1.unterminated_c_str(), str1.GetLength());
  data_->CopyContentsAt(str1.GetLength(), str2.unterminated_c_str(),
                        str2.GetLength());
}

ByteString::ByteString(const std::initializer_list<ByteStringView>& list) {
  FX_SAFE_SIZE_T nSafeLen = 0;
  for (const auto& item : list)
    nSafeLen += item.GetLength();

  size_t nNewLen = nSafeLen.ValueOrDie();
  if (nNewLen == 0)
    return;

  data_.Reset(StringData::Create(nNewLen));

  size_t nOffset = 0;
  for (const auto& item : list) {
    data_->CopyContentsAt(nOffset, item.unterminated_c_str(), item.GetLength());
    nOffset += item.GetLength();
  }
}

ByteString::ByteString(const std::ostringstream& outStream) {
  std::string str = outStream.str();
  if (str.length() > 0)
    data_.Reset(StringData::Create(str.c_str(), str.length()));
}

ByteString::~ByteString() {}

ByteString& ByteString::operator=(const char* str) {
  if (!str || !str[0])
    clear();
  else
    AssignCopy(str, strlen(str));

  return *this;
}

ByteString& ByteString::operator=(ByteStringView str) {
  if (str.IsEmpty())
    clear();
  else
    AssignCopy(str.unterminated_c_str(), str.GetLength());

  return *this;
}

ByteString& ByteString::operator=(const ByteString& that) {
  if (data_ != that.data_)
    data_ = that.data_;

  return *this;
}

ByteString& ByteString::operator=(ByteString&& that) {
  if (data_ != that.data_)
    data_ = std::move(that.data_);

  return *this;
}

ByteString& ByteString::operator+=(const char* str) {
  if (str)
    Concat(str, strlen(str));

  return *this;
}

ByteString& ByteString::operator+=(char ch) {
  Concat(&ch, 1);
  return *this;
}

ByteString& ByteString::operator+=(const ByteString& str) {
  if (str.data_)
    Concat(str.data_->string_, str.data_->data_length_);

  return *this;
}

ByteString& ByteString::operator+=(ByteStringView str) {
  if (!str.IsEmpty())
    Concat(str.unterminated_c_str(), str.GetLength());

  return *this;
}

bool ByteString::operator==(const char* ptr) const {
  if (!data_)
    return !ptr || !ptr[0];

  if (!ptr)
    return data_->data_length_ == 0;

  return strlen(ptr) == data_->data_length_ &&
         memcmp(ptr, data_->string_, data_->data_length_) == 0;
}

bool ByteString::operator==(ByteStringView str) const {
  if (!data_)
    return str.IsEmpty();

  return data_->data_length_ == str.GetLength() &&
         memcmp(data_->string_, str.unterminated_c_str(), str.GetLength()) == 0;
}

bool ByteString::operator==(const ByteString& other) const {
  if (data_ == other.data_)
    return true;

  if (IsEmpty())
    return other.IsEmpty();

  if (other.IsEmpty())
    return false;

  return other.data_->data_length_ == data_->data_length_ &&
         memcmp(other.data_->string_, data_->string_, data_->data_length_) == 0;
}

bool ByteString::operator<(const char* ptr) const {
  if (!data_ && !ptr)
    return false;
  if (c_str() == ptr)
    return false;

  size_t len = GetLength();
  size_t other_len = ptr ? strlen(ptr) : 0;
  int result = memcmp(c_str(), ptr, std::min(len, other_len));
  return result < 0 || (result == 0 && len < other_len);
}

bool ByteString::operator<(ByteStringView str) const {
  return Compare(str) < 0;
}

bool ByteString::operator<(const ByteString& other) const {
  if (data_ == other.data_)
    return false;

  size_t len = GetLength();
  size_t other_len = other.GetLength();
  int result = memcmp(c_str(), other.c_str(), std::min(len, other_len));
  return result < 0 || (result == 0 && len < other_len);
}

bool ByteString::EqualNoCase(ByteStringView str) const {
  if (!data_)
    return str.IsEmpty();

  size_t len = str.GetLength();
  if (data_->data_length_ != len)
    return false;

  const uint8_t* pThis = (const uint8_t*)data_->string_;
  const uint8_t* pThat = str.raw_str();
  for (size_t i = 0; i < len; i++) {
    if ((*pThis) != (*pThat)) {
      uint8_t bThis = tolower(*pThis);
      uint8_t bThat = tolower(*pThat);
      if (bThis != bThat)
        return false;
    }
    pThis++;
    pThat++;
  }
  return true;
}

void ByteString::AssignCopy(const char* pSrcData, size_t nSrcLen) {
  AllocBeforeWrite(nSrcLen);
  data_->CopyContents(pSrcData, nSrcLen);
  data_->data_length_ = nSrcLen;
}

void ByteString::ReallocBeforeWrite(size_t nNewLength) {
  if (data_ && data_->CanOperateInPlace(nNewLength))
    return;

  if (nNewLength == 0) {
    clear();
    return;
  }

  RetainPtr<StringData> pNewData(StringData::Create(nNewLength));
  if (data_) {
    size_t nCopyLength = std::min(data_->data_length_, nNewLength);
    pNewData->CopyContents(data_->string_, nCopyLength);
    pNewData->data_length_ = nCopyLength;
  } else {
    pNewData->data_length_ = 0;
  }
  pNewData->string_[pNewData->data_length_] = 0;
  data_.Swap(pNewData);
}

void ByteString::AllocBeforeWrite(size_t nNewLength) {
  if (data_ && data_->CanOperateInPlace(nNewLength))
    return;

  if (nNewLength == 0) {
    clear();
    return;
  }

  data_.Reset(StringData::Create(nNewLength));
}

void ByteString::ReleaseBuffer(size_t nNewLength) {
  if (!data_)
    return;

  nNewLength = std::min(nNewLength, data_->alloc_length_);
  if (nNewLength == 0) {
    clear();
    return;
  }

  ASSERT(data_->refs_ == 1);
  data_->data_length_ = nNewLength;
  data_->string_[nNewLength] = 0;
  if (data_->alloc_length_ - nNewLength >= 32) {
    // Over arbitrary threshold, so pay the price to relocate.  Force copy to
    // always occur by holding a second reference to the string.
    ByteString preserve(*this);
    ReallocBeforeWrite(nNewLength);
  }
}

void ByteString::Reserve(size_t len) {
  GetBuffer(len);
}

pdfium::span<char> ByteString::GetBuffer(size_t nMinBufLength) {
  if (!data_) {
    if (nMinBufLength == 0)
      return pdfium::span<char>();

    data_.Reset(StringData::Create(nMinBufLength));
    data_->data_length_ = 0;
    data_->string_[0] = 0;
    return pdfium::span<char>(data_->string_, data_->alloc_length_);
  }

  if (data_->CanOperateInPlace(nMinBufLength))
    return pdfium::span<char>(data_->string_, data_->alloc_length_);

  nMinBufLength = std::max(nMinBufLength, data_->data_length_);
  if (nMinBufLength == 0)
    return pdfium::span<char>();

  RetainPtr<StringData> pNewData(StringData::Create(nMinBufLength));
  pNewData->CopyContents(*data_);
  pNewData->data_length_ = data_->data_length_;
  data_.Swap(pNewData);
  return pdfium::span<char>(data_->string_, data_->alloc_length_);
}

size_t ByteString::Delete(size_t index, size_t count) {
  if (!data_)
    return 0;

  size_t old_length = data_->data_length_;
  if (count == 0 || index != pdfium::clamp<size_t>(index, 0, old_length))
    return old_length;

  size_t removal_length = index + count;
  if (removal_length > old_length)
    return old_length;

  ReallocBeforeWrite(old_length);
  size_t chars_to_copy = old_length - removal_length + 1;
  memmove(data_->string_ + index, data_->string_ + removal_length,
          chars_to_copy);
  data_->data_length_ = old_length - count;
  return data_->data_length_;
}

void ByteString::Concat(const char* pSrcData, size_t nSrcLen) {
  if (!pSrcData || nSrcLen == 0)
    return;

  if (!data_) {
    data_.Reset(StringData::Create(pSrcData, nSrcLen));
    return;
  }

  if (data_->CanOperateInPlace(data_->data_length_ + nSrcLen)) {
    data_->CopyContentsAt(data_->data_length_, pSrcData, nSrcLen);
    data_->data_length_ += nSrcLen;
    return;
  }

  size_t nConcatLen = std::max(data_->data_length_ / 2, nSrcLen);
  RetainPtr<StringData> pNewData(
      StringData::Create(data_->data_length_ + nConcatLen));
  pNewData->CopyContents(*data_);
  pNewData->CopyContentsAt(data_->data_length_, pSrcData, nSrcLen);
  pNewData->data_length_ = data_->data_length_ + nSrcLen;
  data_.Swap(pNewData);
}

intptr_t ByteString::ReferenceCountForTesting() const {
  return data_ ? data_->refs_ : 0;
}

ByteString ByteString::Substr(size_t first, size_t count) const {
  if (!data_)
    return ByteString();

  if (!IsValidIndex(first))
    return ByteString();

  if (count == 0 || !IsValidLength(count))
    return ByteString();

  if (!IsValidIndex(first + count - 1))
    return ByteString();

  if (first == 0 && count == data_->data_length_)
    return *this;

  ByteString dest;
  AllocCopy(dest, count, first);
  return dest;
}

ByteString ByteString::First(size_t count) const {
  if (count == 0 || !IsValidLength(count))
    return ByteString();
  return Substr(0, count);
}

ByteString ByteString::Last(size_t count) const {
  if (count == 0 || !IsValidLength(count))
    return ByteString();
  return Substr(GetLength() - count, count);
}

void ByteString::AllocCopy(ByteString& dest,
                           size_t nCopyLen,
                           size_t nCopyIndex) const {
  if (nCopyLen == 0)
    return;

  RetainPtr<StringData> pNewData(
      StringData::Create(data_->string_ + nCopyIndex, nCopyLen));
  dest.data_.Swap(pNewData);
}

void ByteString::SetAt(size_t index, char c) {
  ASSERT(IsValidIndex(index));
  ReallocBeforeWrite(data_->data_length_);
  data_->string_[index] = c;
}

size_t ByteString::Insert(size_t index, char ch) {
  const size_t cur_length = GetLength();
  if (!IsValidLength(index))
    return cur_length;

  const size_t new_length = cur_length + 1;
  ReallocBeforeWrite(new_length);
  memmove(data_->string_ + index + 1, data_->string_ + index,
          new_length - index);
  data_->string_[index] = ch;
  data_->data_length_ = new_length;
  return new_length;
}

Optional<size_t> ByteString::Find(char ch, size_t start) const {
  if (!data_)
    return pdfium::nullopt;

  if (!IsValidIndex(start))
    return pdfium::nullopt;

  const char* pStr = static_cast<const char*>(
      memchr(data_->string_ + start, ch, data_->data_length_ - start));
  return pStr ? Optional<size_t>(static_cast<size_t>(pStr - data_->string_))
              : pdfium::nullopt;
}

Optional<size_t> ByteString::Find(ByteStringView subStr, size_t start) const {
  if (!data_)
    return pdfium::nullopt;

  if (!IsValidIndex(start))
    return pdfium::nullopt;

  const char* pStr =
      FX_strstr(data_->string_ + start, data_->data_length_ - start,
                subStr.unterminated_c_str(), subStr.GetLength());
  return pStr ? Optional<size_t>(static_cast<size_t>(pStr - data_->string_))
              : pdfium::nullopt;
}

Optional<size_t> ByteString::ReverseFind(char ch) const {
  if (!data_)
    return pdfium::nullopt;

  size_t nLength = data_->data_length_;
  while (nLength--) {
    if (data_->string_[nLength] == ch)
      return nLength;
  }
  return pdfium::nullopt;
}

void ByteString::MakeLower() {
  if (!data_)
    return;

  ReallocBeforeWrite(data_->data_length_);
  FXSYS_strlwr(data_->string_);
}

void ByteString::MakeUpper() {
  if (!data_)
    return;

  ReallocBeforeWrite(data_->data_length_);
  FXSYS_strupr(data_->string_);
}

size_t ByteString::Remove(char chRemove) {
  if (!data_ || data_->data_length_ == 0)
    return 0;

  char* pstrSource = data_->string_;
  char* pstrEnd = data_->string_ + data_->data_length_;
  while (pstrSource < pstrEnd) {
    if (*pstrSource == chRemove)
      break;
    pstrSource++;
  }
  if (pstrSource == pstrEnd)
    return 0;

  ptrdiff_t copied = pstrSource - data_->string_;
  ReallocBeforeWrite(data_->data_length_);
  pstrSource = data_->string_ + copied;
  pstrEnd = data_->string_ + data_->data_length_;

  char* pstrDest = pstrSource;
  while (pstrSource < pstrEnd) {
    if (*pstrSource != chRemove) {
      *pstrDest = *pstrSource;
      pstrDest++;
    }
    pstrSource++;
  }

  *pstrDest = 0;
  size_t nCount = static_cast<size_t>(pstrSource - pstrDest);
  data_->data_length_ -= nCount;
  return nCount;
}

size_t ByteString::Replace(ByteStringView pOld, ByteStringView pNew) {
  if (!data_ || pOld.IsEmpty())
    return 0;

  size_t nSourceLen = pOld.GetLength();
  size_t nReplacementLen = pNew.GetLength();
  size_t nCount = 0;
  const char* pStart = data_->string_;
  char* pEnd = data_->string_ + data_->data_length_;
  while (1) {
    const char* pTarget = FX_strstr(pStart, static_cast<int>(pEnd - pStart),
                                    pOld.unterminated_c_str(), nSourceLen);
    if (!pTarget)
      break;

    nCount++;
    pStart = pTarget + nSourceLen;
  }
  if (nCount == 0)
    return 0;

  size_t nNewLength =
      data_->data_length_ + (nReplacementLen - nSourceLen) * nCount;

  if (nNewLength == 0) {
    clear();
    return nCount;
  }

  RetainPtr<StringData> pNewData(StringData::Create(nNewLength));
  pStart = data_->string_;
  char* pDest = pNewData->string_;
  for (size_t i = 0; i < nCount; i++) {
    const char* pTarget = FX_strstr(pStart, static_cast<int>(pEnd - pStart),
                                    pOld.unterminated_c_str(), nSourceLen);
    memcpy(pDest, pStart, pTarget - pStart);
    pDest += pTarget - pStart;
    memcpy(pDest, pNew.unterminated_c_str(), pNew.GetLength());
    pDest += pNew.GetLength();
    pStart = pTarget + nSourceLen;
  }
  memcpy(pDest, pStart, pEnd - pStart);
  data_.Swap(pNewData);
  return nCount;
}

int ByteString::Compare(ByteStringView str) const {
  if (!data_)
    return str.IsEmpty() ? 0 : -1;

  size_t this_len = data_->data_length_;
  size_t that_len = str.GetLength();
  size_t min_len = std::min(this_len, that_len);
  int result = memcmp(data_->string_, str.unterminated_c_str(), min_len);
  if (result != 0)
    return result;
  if (this_len == that_len)
    return 0;
  return this_len < that_len ? -1 : 1;
}

void ByteString::Trim() {
  TrimRight(kTrimChars);
  TrimLeft(kTrimChars);
}

void ByteString::Trim(char target) {
  ByteStringView targets(target);
  TrimRight(targets);
  TrimLeft(targets);
}

void ByteString::Trim(ByteStringView targets) {
  TrimRight(targets);
  TrimLeft(targets);
}

void ByteString::TrimLeft() {
  TrimLeft(kTrimChars);
}

void ByteString::TrimLeft(char target) {
  TrimLeft(ByteStringView(target));
}

void ByteString::TrimLeft(ByteStringView targets) {
  if (!data_ || targets.IsEmpty())
    return;

  size_t len = GetLength();
  if (len == 0)
    return;

  size_t pos = 0;
  while (pos < len) {
    size_t i = 0;
    while (i < targets.GetLength() && targets[i] != data_->string_[pos])
      i++;
    if (i == targets.GetLength())
      break;
    pos++;
  }
  if (pos) {
    ReallocBeforeWrite(len);
    size_t nDataLength = len - pos;
    memmove(data_->string_, data_->string_ + pos,
            (nDataLength + 1) * sizeof(char));
    data_->data_length_ = nDataLength;
  }
}

void ByteString::TrimRight() {
  TrimRight(kTrimChars);
}

void ByteString::TrimRight(char target) {
  TrimRight(ByteStringView(target));
}

void ByteString::TrimRight(ByteStringView targets) {
  if (!data_ || targets.IsEmpty())
    return;

  size_t pos = GetLength();
  if (pos == 0)
    return;

  while (pos) {
    size_t i = 0;
    while (i < targets.GetLength() && targets[i] != data_->string_[pos - 1])
      i++;
    if (i == targets.GetLength())
      break;
    pos--;
  }
  if (pos < data_->data_length_) {
    ReallocBeforeWrite(data_->data_length_);
    data_->string_[pos] = 0;
    data_->data_length_ = pos;
  }
}

std::ostream& operator<<(std::ostream& os, const ByteString& str) {
  return os.write(str.c_str(), str.GetLength());
}

std::ostream& operator<<(std::ostream& os, ByteStringView str) {
  return os.write(str.unterminated_c_str(), str.GetLength());
}

}  // namespace fxcrt

uint32_t FX_HashCode_GetA(ByteStringView str, bool bIgnoreCase) {
  uint32_t dwHashCode = 0;
  if (bIgnoreCase) {
    for (ByteStringView::UnsignedType c : str)
      dwHashCode = 31 * dwHashCode + tolower(c);
  } else {
    for (ByteStringView::UnsignedType c : str)
      dwHashCode = 31 * dwHashCode + c;
  }
  return dwHashCode;
}

uint32_t FX_HashCode_GetAsIfW(ByteStringView str, bool bIgnoreCase) {
  uint32_t dwHashCode = 0;
  if (bIgnoreCase) {
    for (ByteStringView::UnsignedType c : str)
      dwHashCode = 1313 * dwHashCode + FXSYS_towlower(c);
  } else {
    for (ByteStringView::UnsignedType c : str)
      dwHashCode = 1313 * dwHashCode + c;
  }
  return dwHashCode;
}
