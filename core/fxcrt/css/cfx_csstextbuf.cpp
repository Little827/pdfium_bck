// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_csstextbuf.h"

#include <utility>

CFX_CSSTextBuf::CFX_CSSTextBuf() = default;

CFX_CSSTextBuf::~CFX_CSSTextBuf() = default;

void CFX_CSSTextBuf::AppendCharIfNotLeadingBlank(wchar_t wch) {
  if (m_iDatLen == 0 && wch <= ' ')
    return;

  if (m_iDatLen >= m_iBufLen) {
    size_t iDesiredSize = std::max<size_t>(32, 2 * m_iBufLen);
    m_pBuffer.reset(FX_Realloc(wchar_t, m_pBuffer.release(), iDesiredSize));
    m_iBufLen = iDesiredSize;
  }

  m_pBuffer.get()[m_iDatLen++] = wch;
}

WideStringView CFX_CSSTextBuf::GetTrailingBlankTrimmedString() const {
  size_t current_len = m_iDatLen;
  while (current_len && m_pBuffer.get()[current_len - 1] <= ' ')
    --current_len;

  return WideStringView(m_pBuffer.get(), current_len);
}
