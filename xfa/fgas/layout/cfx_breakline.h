// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FGAS_LAYOUT_CFX_BREAKLINE_H_
#define XFA_FGAS_LAYOUT_CFX_BREAKLINE_H_

#include <csignal>
#include <iostream>
#include <vector>

#include "core/fxcrt/cfx_char.h"
#include "xfa/fgas/layout/cfx_breakpiece.h"

class CFX_BreakLine {
 public:
  CFX_BreakLine();
  ~CFX_BreakLine();

  int32_t CountChars() const;
  CFX_Char* GetChar(int32_t index);
  const CFX_Char* GetChar(int32_t index) const;

  int32_t CountPieces() const;
  const CFX_BreakPiece* GetPiece(int32_t index) const;

  int32_t GetLineEnd() const;

  void Clear();

  std::vector<CFX_Char> m_LineChars;
  std::vector<CFX_BreakPiece> m_LinePieces;
  int32_t m_iStart;

  void IncreaseWidth(int32_t d) {
    m_iWidth += d;
    // std::cerr << "IncreaseWidth by " << d << " to " << m_iWidth << std::endl;
    // if (d == 50720) raise(SIGSEGV);
  }

  void SetWidth(int32_t v) {
    m_iWidth = v;
    // std::cerr << "SetWidth to " << v << std::endl;
  }

  int32_t GetWidth() {
    // std::cerr << "GetWidth returns " << m_iWidth << std::endl;
    return m_iWidth;
  }

 private:
  int32_t m_iWidth;

 public:
  int32_t m_iArabicChars;
};

#endif  // XFA_FGAS_LAYOUT_CFX_BREAKLINE_H_
