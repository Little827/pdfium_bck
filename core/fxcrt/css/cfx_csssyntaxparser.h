// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CSS_CFX_CSSSYNTAXPARSER_H_
#define CORE_FXCRT_CSS_CFX_CSSSYNTAXPARSER_H_

#include <stack>

#include "core/fxcrt/css/cfx_cssexttextbuf.h"
#include "core/fxcrt/css/cfx_csstextbuf.h"
#include "core/fxcrt/fx_string.h"

#define CFX_CSSSYNTAXCHECK_AllowCharset 1
#define CFX_CSSSYNTAXCHECK_AllowImport 2

enum class CFX_CSSSyntaxStatus : uint8_t {
  Error,
  EOS,
  None,
  StyleRule,
  Selector,
  DeclOpen,
  DeclClose,
  PropertyName,
  PropertyValue,
};

class CFX_CSSSyntaxParser {
 public:
  CFX_CSSSyntaxParser(const wchar_t* pBuffer,
                      int32_t iBufferSize,
                      bool bOnlyDeclaration);
  ~CFX_CSSSyntaxParser();

  CFX_CSSSyntaxStatus DoSyntaxParse();
  WideStringView GetCurrentString() const;

 private:
  enum class SyntaxMode : uint8_t {
    RuleSet,
    Comment,
    UnknownRule,
    Selector,
    PropertyName,
    PropertyValue,
  };

  void SwitchMode(SyntaxMode eMode);
  int32_t SwitchToComment();

  bool RestoreMode();
  void AppendCharIfNotLeadingBlank(wchar_t wch);
  void SaveTextData();

  SyntaxMode m_eMode = SyntaxMode::RuleSet;
  CFX_CSSSyntaxStatus m_eStatus = CFX_CSSSyntaxStatus::None;
  int32_t m_iTextDataLen = 0;
  CFX_CSSTextBuf m_TextData;
  CFX_CSSExtTextBuf m_TextPlane;
  std::stack<SyntaxMode> m_ModeStack;
};

#endif  // CORE_FXCRT_CSS_CFX_CSSSYNTAXPARSER_H_
