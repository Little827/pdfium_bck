// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/css/cfx_csssyntaxparser.h"

#include <algorithm>

#include "core/fxcrt/css/cfx_cssdata.h"
#include "core/fxcrt/css/cfx_cssdeclaration.h"
#include "core/fxcrt/fx_codepage.h"
#include "core/fxcrt/fx_extension.h"
#include "third_party/base/compiler_specific.h"
#include "third_party/base/logging.h"

namespace {

bool IsSelectorStart(wchar_t wch) {
  return wch == '.' || wch == '#' || wch == '*' ||
         (isascii(wch) && isalpha(wch));
}

}  // namespace

CFX_CSSSyntaxParser::CFX_CSSSyntaxParser(WideStringView str) : input_(str) {}

CFX_CSSSyntaxParser::~CFX_CSSSyntaxParser() = default;

void CFX_CSSSyntaxParser::SetParseOnlyDeclarations() {
  mode_ = SyntaxMode::kPropertyName;
}

CFX_CSSSyntaxStatus CFX_CSSSyntaxParser::DoSyntaxParse() {
  output_.Clear();
  if (error_)
    return CFX_CSSSyntaxStatus::kError;

  while (!input_.IsEOF()) {
    wchar_t wch = input_.GetChar();
    switch (mode_) {
      case SyntaxMode::kRuleSet:
        switch (wch) {
          case '}':
            error_ = true;
            return CFX_CSSSyntaxStatus::kError;
          case '/':
            if (input_.GetNextChar() == '*') {
              SaveMode(SyntaxMode::kRuleSet);
              mode_ = SyntaxMode::kComment;
              break;
            }
            FALLTHROUGH;
          default:
            if (wch <= ' ') {
              input_.MoveNext();
            } else if (IsSelectorStart(wch)) {
              mode_ = SyntaxMode::kSelector;
              return CFX_CSSSyntaxStatus::kStyleRule;
            } else {
              error_ = true;
              return CFX_CSSSyntaxStatus::kError;
            }
            break;
        }
        break;
      case SyntaxMode::kSelector:
        switch (wch) {
          case ',':
            input_.MoveNext();
            if (!output_.IsEmpty())
              return CFX_CSSSyntaxStatus::kSelector;
            break;
          case '{':
            if (!output_.IsEmpty())
              return CFX_CSSSyntaxStatus::kSelector;
            input_.MoveNext();
            SaveMode(SyntaxMode::kRuleSet);  // Back to validate ruleset again.
            mode_ = SyntaxMode::kPropertyName;
            return CFX_CSSSyntaxStatus::kDeclOpen;
          case '/':
            if (input_.GetNextChar() == '*') {
              SaveMode(SyntaxMode::kSelector);
              mode_ = SyntaxMode::kComment;
              if (!output_.IsEmpty())
                return CFX_CSSSyntaxStatus::kSelector;
              break;
            }
            FALLTHROUGH;
          default:
            output_.AppendCharIfNotLeadingBlank(wch);
            input_.MoveNext();
            break;
        }
        break;
      case SyntaxMode::kPropertyName:
        switch (wch) {
          case ':':
            input_.MoveNext();
            mode_ = SyntaxMode::kPropertyValue;
            return CFX_CSSSyntaxStatus::kPropertyName;
          case '}':
            input_.MoveNext();
            if (!RestoreMode())
              return CFX_CSSSyntaxStatus::kError;

            return CFX_CSSSyntaxStatus::kDeclClose;
          case '/':
            if (input_.GetNextChar() == '*') {
              SaveMode(SyntaxMode::kPropertyName);
              mode_ = SyntaxMode::kComment;
              if (!output_.IsEmpty())
                return CFX_CSSSyntaxStatus::kPropertyName;
              break;
            }
            FALLTHROUGH;
          default:
            output_.AppendCharIfNotLeadingBlank(wch);
            input_.MoveNext();
            break;
        }
        break;
      case SyntaxMode::kPropertyValue:
        switch (wch) {
          case ';':
            input_.MoveNext();
            FALLTHROUGH;
          case '}':
            mode_ = SyntaxMode::kPropertyName;
            return CFX_CSSSyntaxStatus::kPropertyValue;
          case '/':
            if (input_.GetNextChar() == '*') {
              SaveMode(SyntaxMode::kPropertyValue);
              mode_ = SyntaxMode::kComment;
              if (!output_.IsEmpty())
                return CFX_CSSSyntaxStatus::kPropertyValue;
              break;
            }
            FALLTHROUGH;
          default:
            output_.AppendCharIfNotLeadingBlank(wch);
            input_.MoveNext();
            break;
        }
        break;
      case SyntaxMode::kComment:
        if (wch == '*' && input_.GetNextChar() == '/') {
          if (!RestoreMode())
            return CFX_CSSSyntaxStatus::kError;
          input_.MoveNext();
        }
        input_.MoveNext();
        break;
      default:
        NOTREACHED();
        break;
    }
  }
  if (mode_ == SyntaxMode::kPropertyValue && !output_.IsEmpty())
    return CFX_CSSSyntaxStatus::kPropertyValue;

  return CFX_CSSSyntaxStatus::kEOS;
}

void CFX_CSSSyntaxParser::SaveMode(SyntaxMode mode) {
  mode_stack_.push(mode);
}

bool CFX_CSSSyntaxParser::RestoreMode() {
  if (mode_stack_.empty()) {
    error_ = true;
    return false;
  }
  mode_ = mode_stack_.top();
  mode_stack_.pop();
  return true;
}

WideStringView CFX_CSSSyntaxParser::GetCurrentString() const {
  return output_.GetTrailingBlankTrimmedString();
}
