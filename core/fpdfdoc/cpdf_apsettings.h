// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFDOC_CPDF_APSETTINGS_H_
#define CORE_FPDFDOC_CPDF_APSETTINGS_H_

#include <utility>

#include "core/fpdfdoc/cpdf_iconfit.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/retain_ptr.h"
#include "core/fxge/cfx_color.h"
#include "core/fxge/dib/fx_dib.h"

class CPDF_Dictionary;
class CPDF_FormControl;
class CPDF_Stream;

class CPDF_ApSettings {
 public:
  // Corresponds to PDF spec section 12.5.6.19 (Widget annotation TP
  // dictionary).
  enum class TextPosition {
    kCaption = 0,
    kIcon = 1,
    kBelow = 2,
    kAbove = 3,
    kRight = 4,
    kLeft = 5,
    kOverlaid = 6,
  };

  explicit CPDF_ApSettings(CPDF_Dictionary* pDict);
  CPDF_ApSettings(const CPDF_ApSettings& that);
  ~CPDF_ApSettings();

  bool HasMKEntry(const ByteString& csEntry) const;
  int GetRotation() const;

  CPDF_IconFit GetIconFit() const;
  TextPosition GetTextPosition() const;

  std::pair<CFX_Color::Type, FX_ARGB> GetColorARGB(
      const ByteString& csEntry) const;

  float GetOriginalColorComponent(int index, const ByteString& csEntry) const;
  CFX_Color GetOriginalColor(const ByteString& csEntry) const;

  WideString GetCaption(const ByteString& csEntry) const;
  CPDF_Stream* GetIcon(const ByteString& csEntry) const;

 private:
  RetainPtr<CPDF_Dictionary> const m_pDict;
};

#endif  // CORE_FPDFDOC_CPDF_APSETTINGS_H_
