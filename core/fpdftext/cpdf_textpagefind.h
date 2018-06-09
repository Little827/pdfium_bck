// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFTEXT_CPDF_TEXTPAGEFIND_H_
#define CORE_FPDFTEXT_CPDF_TEXTPAGEFIND_H_

#include <vector>

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/optional.h"

class CPDF_TextPage;

class CPDF_TextPageFind {
 public:
  CPDF_TextPageFind(const CPDF_TextPage* pTextPage,
                    const std::vector<WideString>& findwhat,
                    bool bMatchCase,
                    bool bMatchWholeWord);
  ~CPDF_TextPageFind();

  static std::vector<WideString> ExtractFindWhat(const WideString& findwhat);

  bool FindFirst(Optional<size_t> startPos);
  bool FindNext();
  bool FindPrev();
  int GetCurOrder() const;
  int GetMatchedCount() const;

 protected:
  bool IsMatchWholeWord(const WideString& csPageText,
                        size_t startPos,
                        size_t endPos);
  int GetCharIndex(int index) const;

 private:
  UnownedPtr<const CPDF_TextPage> const m_pTextPage;
  WideString m_strText;
  std::vector<uint16_t> m_CharIndex;
  const std::vector<WideString> m_csFindWhatArray;
  Optional<size_t> m_findNextStart;
  Optional<size_t> m_findPreStart;
  int m_resStart = 0;
  int m_resEnd = -1;
  const bool m_bMatchCase;
  const bool m_bMatchWholeWord;
};

#endif  // CORE_FPDFTEXT_CPDF_TEXTPAGEFIND_H_
