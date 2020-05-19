// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/widestring.h"

#include <stddef.h>

#include <algorithm>
#include <cctype>
#include <cwctype>

#include "core/fxcrt/fx_codepage.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/string_pool_template.h"
#include "third_party/base/numerics/safe_math.h"
#include "third_party/base/stl_util.h"

template class fxcrt::StringDataTemplate<wchar_t>;
template class fxcrt::StringViewTemplate<wchar_t>;
template class fxcrt::StringPoolTemplate<WideString>;
template struct std::hash<WideString>;

#define FORCE_ANSI 0x10000
#define FORCE_UNICODE 0x20000
#define FORCE_INT64 0x40000

namespace {

constexpr wchar_t kWideTrimChars[] = L"\x09\x0a\x0b\x0c\x0d\x20";

const wchar_t* FX_wcsstr(const wchar_t* haystack,
                         int haystack_len,
                         const wchar_t* needle,
                         int needle_len) {
  if (needle_len > haystack_len || needle_len == 0) {
    return nullptr;
  }
  const wchar_t* end_ptr = haystack + haystack_len - needle_len;
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

Optional<size_t> GuessSizeForVSWPrintf(const wchar_t* pFormat,
                                       va_list argList) {
  size_t nMaxLen = 0;
  for (const wchar_t* pStr = pFormat; *pStr != 0; pStr++) {
    if (*pStr != '%' || *(pStr = pStr + 1) == '%') {
      ++nMaxLen;
      continue;
    }
    int nItemLen = 0;
    int nWidth = 0;
    for (; *pStr != 0; pStr++) {
      if (*pStr == '#') {
        nMaxLen += 2;
      } else if (*pStr == '*') {
        nWidth = va_arg(argList, int);
      } else if (*pStr != '-' && *pStr != '+' && *pStr != '0' && *pStr != ' ') {
        break;
      }
    }
    if (nWidth == 0) {
      nWidth = FXSYS_wtoi(pStr);
      while (FXSYS_IsDecimalDigit(*pStr))
        ++pStr;
    }
    if (nWidth < 0 || nWidth > 128 * 1024)
      return pdfium::nullopt;
    int nPrecision = 0;
    if (*pStr == '.') {
      pStr++;
      if (*pStr == '*') {
        nPrecision = va_arg(argList, int);
        pStr++;
      } else {
        nPrecision = FXSYS_wtoi(pStr);
        while (FXSYS_IsDecimalDigit(*pStr))
          ++pStr;
      }
    }
    if (nPrecision < 0 || nPrecision > 128 * 1024)
      return pdfium::nullopt;
    int nModifier = 0;
    if (*pStr == L'I' && *(pStr + 1) == L'6' && *(pStr + 2) == L'4') {
      pStr += 3;
      nModifier = FORCE_INT64;
    } else {
      switch (*pStr) {
        case 'h':
          nModifier = FORCE_ANSI;
          pStr++;
          break;
        case 'l':
          nModifier = FORCE_UNICODE;
          pStr++;
          break;
        case 'F':
        case 'N':
        case 'L':
          pStr++;
          break;
      }
    }
    switch (*pStr | nModifier) {
      case 'c':
      case 'C':
        nItemLen = 2;
        va_arg(argList, int);
        break;
      case 'c' | FORCE_ANSI:
      case 'C' | FORCE_ANSI:
        nItemLen = 2;
        va_arg(argList, int);
        break;
      case 'c' | FORCE_UNICODE:
      case 'C' | FORCE_UNICODE:
        nItemLen = 2;
        va_arg(argList, int);
        break;
      case 's': {
        const wchar_t* pstrNextArg = va_arg(argList, const wchar_t*);
        if (pstrNextArg) {
          nItemLen = wcslen(pstrNextArg);
          if (nItemLen < 1) {
            nItemLen = 1;
          }
        } else {
          nItemLen = 6;
        }
      } break;
      case 'S': {
        const char* pstrNextArg = va_arg(argList, const char*);
        if (pstrNextArg) {
          nItemLen = strlen(pstrNextArg);
          if (nItemLen < 1) {
            nItemLen = 1;
          }
        } else {
          nItemLen = 6;
        }
      } break;
      case 's' | FORCE_ANSI:
      case 'S' | FORCE_ANSI: {
        const char* pstrNextArg = va_arg(argList, const char*);
        if (pstrNextArg) {
          nItemLen = strlen(pstrNextArg);
          if (nItemLen < 1) {
            nItemLen = 1;
          }
        } else {
          nItemLen = 6;
        }
      } break;
      case 's' | FORCE_UNICODE:
      case 'S' | FORCE_UNICODE: {
        const wchar_t* pstrNextArg = va_arg(argList, wchar_t*);
        if (pstrNextArg) {
          nItemLen = wcslen(pstrNextArg);
          if (nItemLen < 1) {
            nItemLen = 1;
          }
        } else {
          nItemLen = 6;
        }
      } break;
    }
    if (nItemLen != 0) {
      if (nPrecision != 0 && nItemLen > nPrecision) {
        nItemLen = nPrecision;
      }
      if (nItemLen < nWidth) {
        nItemLen = nWidth;
      }
    } else {
      switch (*pStr) {
        case 'd':
        case 'i':
        case 'u':
        case 'x':
        case 'X':
        case 'o':
          if (nModifier & FORCE_INT64) {
            va_arg(argList, int64_t);
          } else {
            va_arg(argList, int);
          }
          nItemLen = 32;
          if (nItemLen < nWidth + nPrecision) {
            nItemLen = nWidth + nPrecision;
          }
          break;
        case 'a':
        case 'A':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
          va_arg(argList, double);
          nItemLen = 128;
          if (nItemLen < nWidth + nPrecision) {
            nItemLen = nWidth + nPrecision;
          }
          break;
        case 'f':
          if (nWidth + nPrecision > 100) {
            nItemLen = nPrecision + nWidth + 128;
          } else {
            double f;
            char pszTemp[256];
            f = va_arg(argList, double);
            FXSYS_snprintf(pszTemp, sizeof(pszTemp), "%*.*f", nWidth,
                           nPrecision + 6, f);
            nItemLen = strlen(pszTemp);
          }
          break;
        case 'p':
          va_arg(argList, void*);
          nItemLen = 32;
          if (nItemLen < nWidth + nPrecision) {
            nItemLen = nWidth + nPrecision;
          }
          break;
        case 'n':
          va_arg(argList, int*);
          break;
      }
    }
    nMaxLen += nItemLen;
  }
  nMaxLen += 32;  // Fudge factor.
  return nMaxLen;
}

// Returns string unless we ran out of space.
Optional<WideString> TryVSWPrintf(size_t size,
                                  const wchar_t* pFormat,
                                  va_list argList) {
  if (!size)
    return {};

  WideString str;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<wchar_t> buffer = str.GetBuffer(size);

    // In the following two calls, there's always space in the WideString
    // for a terminating NUL that's not included in the span.
    // For vswprintf(), MSAN won't untaint the buffer on a truncated write's
    // -1 return code even though the buffer is written. Probably just as well
    // not to trust the vendor's implementation to write anything anyways.
    // See https://crbug.com/705912.
    memset(buffer.data(), 0, (size + 1) * sizeof(wchar_t));
    int ret = vswprintf(buffer.data(), size + 1, pFormat, argList);

    bool bSufficientBuffer = ret >= 0 || buffer[size - 1] == 0;
    if (!bSufficientBuffer)
      return {};
  }
  str.ReleaseBuffer(str.GetStringLength());
  return {str};
}

}  // namespace

namespace fxcrt {

static_assert(sizeof(WideString) <= sizeof(wchar_t*),
              "Strings must not require more space than pointers");

// static
WideString WideString::FormatV(const wchar_t* format, va_list argList) {
  va_list argListCopy;
  va_copy(argListCopy, argList);
  int maxLen = vswprintf(nullptr, 0, format, argListCopy);
  va_end(argListCopy);

  if (maxLen <= 0) {
    va_copy(argListCopy, argList);
    auto guess = GuessSizeForVSWPrintf(format, argListCopy);
    va_end(argListCopy);

    if (!guess.has_value())
      return WideString();
    maxLen = pdfium::base::checked_cast<int>(guess.value());
  }

  while (maxLen < 32 * 1024) {
    va_copy(argListCopy, argList);
    Optional<WideString> ret =
        TryVSWPrintf(static_cast<size_t>(maxLen), format, argListCopy);
    va_end(argListCopy);

    if (ret)
      return *ret;
    maxLen *= 2;
  }
  return WideString();
}

// static
WideString WideString::Format(const wchar_t* pFormat, ...) {
  va_list argList;
  va_start(argList, pFormat);
  WideString ret = FormatV(pFormat, argList);
  va_end(argList);
  return ret;
}

WideString::WideString() {}

WideString::WideString(const WideString& other) : data_(other.data_) {}

WideString::WideString(WideString&& other) noexcept {
  data_.Swap(other.data_);
}

WideString::WideString(const wchar_t* pStr, size_t nLen) {
  if (nLen)
    data_.Reset(StringData::Create(pStr, nLen));
}

WideString::WideString(wchar_t ch) {
  data_.Reset(StringData::Create(1));
  data_->string_[0] = ch;
}

WideString::WideString(const wchar_t* ptr)
    : WideString(ptr, ptr ? wcslen(ptr) : 0) {}

WideString::WideString(WideStringView stringSrc) {
  if (!stringSrc.IsEmpty()) {
    data_.Reset(StringData::Create(stringSrc.unterminated_c_str(),
                                   stringSrc.GetLength()));
  }
}

WideString::WideString(WideStringView str1, WideStringView str2) {
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

WideString::WideString(const std::initializer_list<WideStringView>& list) {
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

WideString::~WideString() {}

WideString& WideString::operator=(const wchar_t* str) {
  if (!str || !str[0])
    clear();
  else
    AssignCopy(str, wcslen(str));

  return *this;
}

WideString& WideString::operator=(WideStringView str) {
  if (str.IsEmpty())
    clear();
  else
    AssignCopy(str.unterminated_c_str(), str.GetLength());

  return *this;
}

WideString& WideString::operator=(const WideString& that) {
  if (data_ != that.data_)
    data_ = that.data_;

  return *this;
}

WideString& WideString::operator=(WideString&& that) {
  if (data_ != that.data_)
    data_ = std::move(that.data_);

  return *this;
}

WideString& WideString::operator+=(const wchar_t* str) {
  if (str)
    Concat(str, wcslen(str));

  return *this;
}

WideString& WideString::operator+=(wchar_t ch) {
  Concat(&ch, 1);
  return *this;
}

WideString& WideString::operator+=(const WideString& str) {
  if (str.data_)
    Concat(str.data_->string_, str.data_->data_length_);

  return *this;
}

WideString& WideString::operator+=(WideStringView str) {
  if (!str.IsEmpty())
    Concat(str.unterminated_c_str(), str.GetLength());

  return *this;
}

bool WideString::operator==(const wchar_t* ptr) const {
  if (!data_)
    return !ptr || !ptr[0];

  if (!ptr)
    return data_->data_length_ == 0;

  return wcslen(ptr) == data_->data_length_ &&
         wmemcmp(ptr, data_->string_, data_->data_length_) == 0;
}

bool WideString::operator==(WideStringView str) const {
  if (!data_)
    return str.IsEmpty();

  return data_->data_length_ == str.GetLength() &&
         wmemcmp(data_->string_, str.unterminated_c_str(), str.GetLength()) ==
             0;
}

bool WideString::operator==(const WideString& other) const {
  if (data_ == other.data_)
    return true;

  if (IsEmpty())
    return other.IsEmpty();

  if (other.IsEmpty())
    return false;

  return other.data_->data_length_ == data_->data_length_ &&
         wmemcmp(other.data_->string_, data_->string_, data_->data_length_) ==
             0;
}

bool WideString::operator<(const wchar_t* ptr) const {
  return Compare(ptr) < 0;
}

bool WideString::operator<(WideStringView str) const {
  if (!data_ && !str.unterminated_c_str())
    return false;
  if (c_str() == str.unterminated_c_str())
    return false;

  size_t len = GetLength();
  size_t other_len = str.GetLength();
  int result =
      wmemcmp(c_str(), str.unterminated_c_str(), std::min(len, other_len));
  return result < 0 || (result == 0 && len < other_len);
}

bool WideString::operator<(const WideString& other) const {
  return Compare(other) < 0;
}

void WideString::AssignCopy(const wchar_t* pSrcData, size_t nSrcLen) {
  AllocBeforeWrite(nSrcLen);
  data_->CopyContents(pSrcData, nSrcLen);
  data_->data_length_ = nSrcLen;
}

void WideString::ReallocBeforeWrite(size_t nNewLength) {
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

void WideString::AllocBeforeWrite(size_t nNewLength) {
  if (data_ && data_->CanOperateInPlace(nNewLength))
    return;

  if (nNewLength == 0) {
    clear();
    return;
  }

  data_.Reset(StringData::Create(nNewLength));
}

void WideString::ReleaseBuffer(size_t nNewLength) {
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
    WideString preserve(*this);
    ReallocBeforeWrite(nNewLength);
  }
}

void WideString::Reserve(size_t len) {
  GetBuffer(len);
}

pdfium::span<wchar_t> WideString::GetBuffer(size_t nMinBufLength) {
  if (!data_) {
    if (nMinBufLength == 0)
      return pdfium::span<wchar_t>();

    data_.Reset(StringData::Create(nMinBufLength));
    data_->data_length_ = 0;
    data_->string_[0] = 0;
    return pdfium::span<wchar_t>(data_->string_, data_->alloc_length_);
  }

  if (data_->CanOperateInPlace(nMinBufLength))
    return pdfium::span<wchar_t>(data_->string_, data_->alloc_length_);

  nMinBufLength = std::max(nMinBufLength, data_->data_length_);
  if (nMinBufLength == 0)
    return pdfium::span<wchar_t>();

  RetainPtr<StringData> pNewData(StringData::Create(nMinBufLength));
  pNewData->CopyContents(*data_);
  pNewData->data_length_ = data_->data_length_;
  data_.Swap(pNewData);
  return pdfium::span<wchar_t>(data_->string_, data_->alloc_length_);
}

size_t WideString::Delete(size_t index, size_t count) {
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
  wmemmove(data_->string_ + index, data_->string_ + removal_length,
           chars_to_copy);
  data_->data_length_ = old_length - count;
  return data_->data_length_;
}

void WideString::Concat(const wchar_t* pSrcData, size_t nSrcLen) {
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

intptr_t WideString::ReferenceCountForTesting() const {
  return data_ ? data_->refs_ : 0;
}

ByteString WideString::ToASCII() const {
  ByteString result;
  result.Reserve(GetLength());
  for (wchar_t wc : *this)
    result.InsertAtBack(static_cast<char>(wc & 0x7f));
  return result;
}

ByteString WideString::ToLatin1() const {
  ByteString result;
  result.Reserve(GetLength());
  for (wchar_t wc : *this)
    result.InsertAtBack(static_cast<char>(wc & 0xff));
  return result;
}

ByteString WideString::ToDefANSI() const {
  int src_len = GetLength();
  int dest_len = FXSYS_WideCharToMultiByte(
      FX_CODEPAGE_DefANSI, 0, c_str(), src_len, nullptr, 0, nullptr, nullptr);
  if (!dest_len)
    return ByteString();

  ByteString bstr;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<char> dest_buf = bstr.GetBuffer(dest_len);
    FXSYS_WideCharToMultiByte(FX_CODEPAGE_DefANSI, 0, c_str(), src_len,
                              dest_buf.data(), dest_len, nullptr, nullptr);
  }
  bstr.ReleaseBuffer(dest_len);
  return bstr;
}

ByteString WideString::ToUTF8() const {
  return FX_UTF8Encode(AsStringView());
}

ByteString WideString::ToUTF16LE() const {
  if (!data_)
    return ByteString("\0\0", 2);

  ByteString result;
  int len = data_->data_length_;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<char> buffer = result.GetBuffer(len * 2 + 2);
    for (int i = 0; i < len; i++) {
      buffer[i * 2] = data_->string_[i] & 0xff;
      buffer[i * 2 + 1] = data_->string_[i] >> 8;
    }
    buffer[len * 2] = 0;
    buffer[len * 2 + 1] = 0;
  }
  result.ReleaseBuffer(len * 2 + 2);
  return result;
}

WideString WideString::Substr(size_t first, size_t count) const {
  if (!data_)
    return WideString();

  if (!IsValidIndex(first))
    return WideString();

  if (count == 0 || !IsValidLength(count))
    return WideString();

  if (!IsValidIndex(first + count - 1))
    return WideString();

  if (first == 0 && count == GetLength())
    return *this;

  WideString dest;
  AllocCopy(dest, count, first);
  return dest;
}

WideString WideString::First(size_t count) const {
  if (count == 0 || !IsValidLength(count))
    return WideString();
  return Substr(0, count);
}

WideString WideString::Last(size_t count) const {
  if (count == 0 || !IsValidLength(count))
    return WideString();
  return Substr(GetLength() - count, count);
}

void WideString::AllocCopy(WideString& dest,
                           size_t nCopyLen,
                           size_t nCopyIndex) const {
  if (nCopyLen == 0)
    return;

  RetainPtr<StringData> pNewData(
      StringData::Create(data_->string_ + nCopyIndex, nCopyLen));
  dest.data_.Swap(pNewData);
}

size_t WideString::Insert(size_t index, wchar_t ch) {
  const size_t cur_length = GetLength();
  if (!IsValidLength(index))
    return cur_length;

  const size_t new_length = cur_length + 1;
  ReallocBeforeWrite(new_length);
  wmemmove(data_->string_ + index + 1, data_->string_ + index,
           new_length - index);
  data_->string_[index] = ch;
  data_->data_length_ = new_length;
  return new_length;
}

Optional<size_t> WideString::Find(wchar_t ch, size_t start) const {
  if (!data_)
    return pdfium::nullopt;

  if (!IsValidIndex(start))
    return pdfium::nullopt;

  const wchar_t* pStr =
      wmemchr(data_->string_ + start, ch, data_->data_length_ - start);
  return pStr ? Optional<size_t>(static_cast<size_t>(pStr - data_->string_))
              : pdfium::nullopt;
}

Optional<size_t> WideString::Find(WideStringView subStr, size_t start) const {
  if (!data_)
    return pdfium::nullopt;

  if (!IsValidIndex(start))
    return pdfium::nullopt;

  const wchar_t* pStr =
      FX_wcsstr(data_->string_ + start, data_->data_length_ - start,
                subStr.unterminated_c_str(), subStr.GetLength());
  return pStr ? Optional<size_t>(static_cast<size_t>(pStr - data_->string_))
              : pdfium::nullopt;
}

Optional<size_t> WideString::ReverseFind(wchar_t ch) const {
  if (!data_)
    return pdfium::nullopt;

  size_t nLength = data_->data_length_;
  while (nLength--) {
    if (data_->string_[nLength] == ch)
      return nLength;
  }
  return pdfium::nullopt;
}

void WideString::MakeLower() {
  if (!data_)
    return;

  ReallocBeforeWrite(data_->data_length_);
  FXSYS_wcslwr(data_->string_);
}

void WideString::MakeUpper() {
  if (!data_)
    return;

  ReallocBeforeWrite(data_->data_length_);
  FXSYS_wcsupr(data_->string_);
}

size_t WideString::Remove(wchar_t chRemove) {
  if (!data_ || data_->data_length_ == 0)
    return 0;

  wchar_t* pstrSource = data_->string_;
  wchar_t* pstrEnd = data_->string_ + data_->data_length_;
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

  wchar_t* pstrDest = pstrSource;
  while (pstrSource < pstrEnd) {
    if (*pstrSource != chRemove) {
      *pstrDest = *pstrSource;
      pstrDest++;
    }
    pstrSource++;
  }

  *pstrDest = 0;
  size_t count = static_cast<size_t>(pstrSource - pstrDest);
  data_->data_length_ -= count;
  return count;
}

size_t WideString::Replace(WideStringView pOld, WideStringView pNew) {
  if (!data_ || pOld.IsEmpty())
    return 0;

  size_t nSourceLen = pOld.GetLength();
  size_t nReplacementLen = pNew.GetLength();
  size_t count = 0;
  const wchar_t* pStart = data_->string_;
  wchar_t* pEnd = data_->string_ + data_->data_length_;
  while (1) {
    const wchar_t* pTarget =
        FX_wcsstr(pStart, static_cast<size_t>(pEnd - pStart),
                  pOld.unterminated_c_str(), nSourceLen);
    if (!pTarget)
      break;

    count++;
    pStart = pTarget + nSourceLen;
  }
  if (count == 0)
    return 0;

  size_t nNewLength =
      data_->data_length_ + (nReplacementLen - nSourceLen) * count;

  if (nNewLength == 0) {
    clear();
    return count;
  }

  RetainPtr<StringData> pNewData(StringData::Create(nNewLength));
  pStart = data_->string_;
  wchar_t* pDest = pNewData->string_;
  for (size_t i = 0; i < count; i++) {
    const wchar_t* pTarget =
        FX_wcsstr(pStart, static_cast<size_t>(pEnd - pStart),
                  pOld.unterminated_c_str(), nSourceLen);
    wmemcpy(pDest, pStart, pTarget - pStart);
    pDest += pTarget - pStart;
    wmemcpy(pDest, pNew.unterminated_c_str(), pNew.GetLength());
    pDest += pNew.GetLength();
    pStart = pTarget + nSourceLen;
  }
  wmemcpy(pDest, pStart, pEnd - pStart);
  data_.Swap(pNewData);
  return count;
}

// static
WideString WideString::FromASCII(ByteStringView bstr) {
  WideString result;
  result.Reserve(bstr.GetLength());
  for (char c : bstr)
    result.InsertAtBack(static_cast<wchar_t>(c & 0x7f));
  return result;
}

// static
WideString WideString::FromLatin1(ByteStringView bstr) {
  WideString result;
  result.Reserve(bstr.GetLength());
  for (char c : bstr)
    result.InsertAtBack(static_cast<wchar_t>(c & 0xff));
  return result;
}

// static
WideString WideString::FromDefANSI(ByteStringView bstr) {
  int src_len = bstr.GetLength();
  int dest_len = FXSYS_MultiByteToWideChar(
      FX_CODEPAGE_DefANSI, 0, bstr.unterminated_c_str(), src_len, nullptr, 0);
  if (!dest_len)
    return WideString();

  WideString wstr;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<wchar_t> dest_buf = wstr.GetBuffer(dest_len);
    FXSYS_MultiByteToWideChar(FX_CODEPAGE_DefANSI, 0, bstr.unterminated_c_str(),
                              src_len, dest_buf.data(), dest_len);
  }
  wstr.ReleaseBuffer(dest_len);
  return wstr;
}

// static
WideString WideString::FromUTF8(ByteStringView str) {
  return FX_UTF8Decode(str);
}

// static
WideString WideString::FromUTF16LE(const unsigned short* wstr, size_t wlen) {
  if (!wstr || wlen == 0)
    return WideString();

  WideString result;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<wchar_t> buf = result.GetBuffer(wlen);
    for (size_t i = 0; i < wlen; i++)
      buf[i] = wstr[i];
  }
  result.ReleaseBuffer(wlen);
  return result;
}

WideString WideString::FromUTF16BE(const unsigned short* wstr, size_t wlen) {
  if (!wstr || wlen == 0)
    return WideString();

  WideString result;
  {
    // Span's lifetime must end before ReleaseBuffer() below.
    pdfium::span<wchar_t> buf = result.GetBuffer(wlen);
    for (size_t i = 0; i < wlen; i++) {
      auto wch = wstr[i];
      wch = (wch >> 8) | (wch << 8);
      buf[i] = wch;
    }
  }
  result.ReleaseBuffer(wlen);
  return result;
}

void WideString::SetAt(size_t index, wchar_t c) {
  ASSERT(IsValidIndex(index));
  ReallocBeforeWrite(data_->data_length_);
  data_->string_[index] = c;
}

int WideString::Compare(const wchar_t* str) const {
  if (data_)
    return str ? wcscmp(data_->string_, str) : 1;
  return (!str || str[0] == 0) ? 0 : -1;
}

int WideString::Compare(const WideString& str) const {
  if (!data_)
    return str.data_ ? -1 : 0;
  if (!str.data_)
    return 1;

  size_t this_len = data_->data_length_;
  size_t that_len = str.data_->data_length_;
  size_t min_len = std::min(this_len, that_len);
  int result = wmemcmp(data_->string_, str.data_->string_, min_len);
  if (result != 0)
    return result;
  if (this_len == that_len)
    return 0;
  return this_len < that_len ? -1 : 1;
}

int WideString::CompareNoCase(const wchar_t* str) const {
  if (data_)
    return str ? FXSYS_wcsicmp(data_->string_, str) : 1;
  return (!str || str[0] == 0) ? 0 : -1;
}

size_t WideString::WStringLength(const unsigned short* str) {
  size_t len = 0;
  if (str)
    while (str[len])
      len++;
  return len;
}

void WideString::Trim() {
  TrimRight(kWideTrimChars);
  TrimLeft(kWideTrimChars);
}

void WideString::Trim(wchar_t target) {
  wchar_t str[2] = {target, 0};
  TrimRight(str);
  TrimLeft(str);
}

void WideString::Trim(WideStringView targets) {
  TrimRight(targets);
  TrimLeft(targets);
}

void WideString::TrimLeft() {
  TrimLeft(kWideTrimChars);
}

void WideString::TrimLeft(wchar_t target) {
  wchar_t str[2] = {target, 0};
  TrimLeft(str);
}

void WideString::TrimLeft(WideStringView targets) {
  if (!data_ || targets.IsEmpty())
    return;

  size_t len = GetLength();
  if (len == 0)
    return;

  size_t pos = 0;
  while (pos < len) {
    size_t i = 0;
    while (i < targets.GetLength() &&
           targets.CharAt(i) != data_->string_[pos]) {
      i++;
    }
    if (i == targets.GetLength())
      break;
    pos++;
  }
  if (!pos)
    return;

  ReallocBeforeWrite(len);
  size_t nDataLength = len - pos;
  memmove(data_->string_, data_->string_ + pos,
          (nDataLength + 1) * sizeof(wchar_t));
  data_->data_length_ = nDataLength;
}

void WideString::TrimRight() {
  TrimRight(kWideTrimChars);
}

void WideString::TrimRight(wchar_t target) {
  wchar_t str[2] = {target, 0};
  TrimRight(str);
}

void WideString::TrimRight(WideStringView targets) {
  if (IsEmpty() || targets.IsEmpty())
    return;

  size_t pos = GetLength();
  while (pos && targets.Contains(data_->string_[pos - 1]))
    pos--;

  if (pos < data_->data_length_) {
    ReallocBeforeWrite(data_->data_length_);
    data_->string_[pos] = 0;
    data_->data_length_ = pos;
  }
}

int WideString::GetInteger() const {
  return data_ ? FXSYS_wtoi(data_->string_) : 0;
}

std::wostream& operator<<(std::wostream& os, const WideString& str) {
  return os.write(str.c_str(), str.GetLength());
}

std::ostream& operator<<(std::ostream& os, const WideString& str) {
  os << str.ToUTF8();
  return os;
}

std::wostream& operator<<(std::wostream& os, WideStringView str) {
  return os.write(str.unterminated_c_str(), str.GetLength());
}

std::ostream& operator<<(std::ostream& os, WideStringView str) {
  os << FX_UTF8Encode(str);
  return os;
}

}  // namespace fxcrt

uint32_t FX_HashCode_GetW(WideStringView str, bool bIgnoreCase) {
  uint32_t dwHashCode = 0;
  if (bIgnoreCase) {
    for (wchar_t c : str)  // match FXSYS_towlower() arg type.
      dwHashCode = 1313 * dwHashCode + FXSYS_towlower(c);
  } else {
    for (WideStringView::UnsignedType c : str)
      dwHashCode = 1313 * dwHashCode + c;
  }
  return dwHashCode;
}
