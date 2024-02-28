// Copyright 2017 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_cssvaluelistparser.h"

#include "core/fxcrt/check.h"
#include "core/fxcrt/check_op.h"
#include "core/fxcrt/compiler_specific.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_system.h"

CFX_CSSValueListParser::CFX_CSSValueListParser(WideStringView list,
                                               wchar_t separator)
    : m_Cur(list), m_Separator(separator) {
  DCHECK(!m_Cur.IsEmpty());
}

CFX_CSSValueListParser::~CFX_CSSValueListParser() = default;

std::optional<WideStringView> CFX_CSSValueListParser::NextValue(
    CFX_CSSValue::PrimitiveType* eType) {
  while (CharsRemain() &&
         (CurrentChar() <= ' ' || CurrentChar() == m_Separator)) {
    Advance();
  }
  if (!CharsRemain()) {
    return std::nullopt;
  }
  *eType = CFX_CSSValue::PrimitiveType::kUnknown;
  const wchar_t* pStart = m_Cur.unterminated_c_str();
  size_t nLength = 0;
  wchar_t wch = CurrentChar();
  if (wch == '#') {
    nLength = SkipToChar(' ');
    if (nLength == 4 || nLength == 7) {
      *eType = CFX_CSSValue::PrimitiveType::kRGB;
    }
  } else if (FXSYS_IsDecimalDigit(wch) || wch == '.' || wch == '-' ||
             wch == '+') {
    while (CharsRemain() &&
           (CurrentChar() > ' ' && CurrentChar() != m_Separator)) {
      Advance();
    }
    nLength = m_Cur.unterminated_c_str() - pStart;
    *eType = CFX_CSSValue::PrimitiveType::kNumber;
  } else if (wch == '\"' || wch == '\'') {
    UNSAFE_BUFFERS(++pStart);
    Advance();
    nLength = SkipToChar(wch);
    Advance();
    *eType = CFX_CSSValue::PrimitiveType::kString;
  } else if (m_Cur.GetLength() > 5 && m_Cur[3] == '(') {
    if (FXSYS_wcsnicmp(L"rgb", m_Cur.unterminated_c_str(), 3) == 0) {
      nLength = SkipToChar(')') + 1;
      Advance();
      *eType = CFX_CSSValue::PrimitiveType::kRGB;
    }
  } else {
    nLength = SkipToCharMatchingParens(m_Separator);
    *eType = CFX_CSSValue::PrimitiveType::kString;
  }
  if (nLength > 0) {
    return WideStringView(pStart, nLength);
  }
  return std::nullopt;
}

size_t CFX_CSSValueListParser::SkipToChar(wchar_t wch) {
  size_t count = 0;
  while (CharsRemain() && CurrentChar() != wch) {
    Advance();
    ++count;
  }
  return count;
}

size_t CFX_CSSValueListParser::SkipToCharMatchingParens(wchar_t wch) {
  const wchar_t* pStart = m_Cur.unterminated_c_str();
  int64_t bracketCount = 0;
  while (CharsRemain() && CurrentChar() != wch) {
    if (CurrentChar() <= ' ') {
      break;
    }
    if (CurrentChar() == '(') {
      bracketCount++;
    } else if (CurrentChar() == ')') {
      bracketCount--;
    }
    Advance();
  }
  while (bracketCount > 0 && CharsRemain()) {
    if (CurrentChar() == ')') {
      bracketCount--;
    }
    Advance();
  }
  return m_Cur.unterminated_c_str() - pStart;
}
