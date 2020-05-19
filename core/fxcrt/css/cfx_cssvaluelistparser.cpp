// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_cssvaluelistparser.h"

#include "core/fxcrt/fx_extension.h"

CFX_CSSValueListParser::CFX_CSSValueListParser(const wchar_t* psz,
                                               int32_t iLen,
                                               wchar_t separator)
    : separator_(separator), cur_(psz), end_(psz + iLen) {
  ASSERT(psz);
  ASSERT(iLen > 0);
}

bool CFX_CSSValueListParser::NextValue(CFX_CSSPrimitiveType* eType,
                                       const wchar_t** pStart,
                                       int32_t* iLength) {
  while (cur_ < end_ && (*cur_ <= ' ' || *cur_ == separator_))
    ++cur_;

  if (cur_ >= end_)
    return false;

  *eType = CFX_CSSPrimitiveType::Unknown;
  *pStart = cur_;
  *iLength = 0;
  wchar_t wch = *cur_;
  if (wch == '#') {
    *iLength = SkipTo(' ', false, false);
    if (*iLength == 4 || *iLength == 7)
      *eType = CFX_CSSPrimitiveType::RGB;
  } else if (FXSYS_IsDecimalDigit(wch) || wch == '.' || wch == '-' ||
             wch == '+') {
    while (cur_ < end_ && (*cur_ > ' ' && *cur_ != separator_))
      ++cur_;

    *iLength = cur_ - *pStart;
    *eType = CFX_CSSPrimitiveType::Number;
  } else if (wch == '\"' || wch == '\'') {
    ++(*pStart);
    cur_++;
    *iLength = SkipTo(wch, false, false);
    cur_++;
    *eType = CFX_CSSPrimitiveType::String;
  } else if (end_ - cur_ > 5 && cur_[3] == '(') {
    if (FXSYS_wcsnicmp(L"rgb", cur_, 3) == 0) {
      *iLength = SkipTo(')', false, false) + 1;
      cur_++;
      *eType = CFX_CSSPrimitiveType::RGB;
    }
  } else {
    *iLength = SkipTo(separator_, true, true);
    *eType = CFX_CSSPrimitiveType::String;
  }
  return cur_ <= end_ && *iLength > 0;
}

int32_t CFX_CSSValueListParser::SkipTo(wchar_t wch,
                                       bool breakOnSpace,
                                       bool matchBrackets) {
  const wchar_t* pStart = cur_;
  int32_t bracketCount = 0;
  while (cur_ < end_ && *cur_ != wch) {
    if (breakOnSpace && *cur_ <= ' ')
      break;
    if (!matchBrackets) {
      cur_++;
      continue;
    }

    if (*cur_ == '(')
      bracketCount++;
    else if (*cur_ == ')')
      bracketCount--;

    cur_++;
  }

  while (bracketCount > 0 && cur_ < end_) {
    if (*cur_ == ')')
      bracketCount--;
    cur_++;
  }
  return cur_ - pStart;
}
