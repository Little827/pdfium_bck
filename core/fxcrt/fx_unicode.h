// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_FX_UNICODE_H_
#define CORE_FXCRT_FX_UNICODE_H_

#include "core/fxcrt/fx_system.h"

uint32_t FX_GetUnicodeProperties(wchar_t wch);
wchar_t FX_GetMirrorChar(wchar_t wch);

#ifdef PDF_ENABLE_XFA

// As defined in http://www.unicode.org/reports/tr14
enum class FX_BREAKPROPERTY : uint8_t {
  kCl0 = 0,
  kCl1 = 1,
  kCl2 = 2,
  kCl3 = 3,
  kCl4 = 4,
  kCl5 = 5,
  kCl6 = 6,
  kCl7 = 7,
  kCl8 = 8,
  kCl9 = 9,
  kCl10 = 10,
  kCl11 = 11,
  kCl12 = 12,
  kCl13 = 13,
  kCl14 = 14,
  kCl15 = 15,
  kCl16 = 16,
  kCl17 = 17,
  kCl18 = 18,
  kCl19 = 19,
  kCl20 = 20,
  kCl21 = 21,
  kCl22 = 22,
  kCl23 = 23,
  kCl24 = 24,
  kCl25 = 25,
  kCl26 = 26,
  kCl27 = 27,
  kCl28 = 28,
  kCl29 = 29,
  kCl30 = 30,
  kCl31 = 31,
  kCl32 = 32,
  kCl33 = 33,
  kCl34 = 34,
  kSpace = 35,
  kCl36 = 36,
  kTab = 37
};

constexpr uint32_t FX_CHARTYPEBITS = 11;

enum FX_CHARTYPE {
  FX_CHARTYPE_Unknown = 0,
  FX_CHARTYPE_Tab = (1 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Space = (2 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Control = (3 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Combination = (4 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Numeric = (5 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Normal = (6 << FX_CHARTYPEBITS),
  FX_CHARTYPE_ArabicAlef = (7 << FX_CHARTYPEBITS),
  FX_CHARTYPE_ArabicSpecial = (8 << FX_CHARTYPEBITS),
  FX_CHARTYPE_ArabicDistortion = (9 << FX_CHARTYPEBITS),
  FX_CHARTYPE_ArabicNormal = (10 << FX_CHARTYPEBITS),
  FX_CHARTYPE_ArabicForm = (11 << FX_CHARTYPEBITS),
  FX_CHARTYPE_Arabic = (12 << FX_CHARTYPEBITS),
};

FX_CHARTYPE GetCharTypeFromProp(uint32_t prop);

// Analagous to ULineBreak in icu's uchar.h, but permuted order, and a
// subset lacking some more recent additions.
FX_BREAKPROPERTY GetBreakPropertyFromProp(uint32_t prop);

wchar_t FX_GetMirrorChar(wchar_t wch, uint32_t dwProps);

#endif  // PDF_ENABLE_XFA

#endif  // CORE_FXCRT_FX_UNICODE_H_
