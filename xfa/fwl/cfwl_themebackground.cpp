// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fwl/cfwl_themebackground.h"

CFWL_ThemeBackground::CFWL_ThemeBackground(CFWL_Widget* pWidget,
                                           CFGAS_GEGraphics* pGraphics)
    : CFWL_ThemePart(pWidget), m_pGraphics(pGraphics) {}

CFWL_ThemeBackground::~CFWL_ThemeBackground() = default;

FWLTHEME_STATE CFWL_ThemeBackground::GetThemeState() const {
  if (dwFWLStates & CFWL_PartState_Disabled)
    return FWLTHEME_STATE::kDisabled;
  if (dwFWLStates & CFWL_PartState_Pressed)
    return FWLTHEME_STATE::kPressed;
  if (dwFWLStates & CFWL_PartState_Hovered)
    return FWLTHEME_STATE::kHover;
  return FWLTHEME_STATE::kNormal;
}
