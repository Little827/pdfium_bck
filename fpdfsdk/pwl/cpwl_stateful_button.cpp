// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fpdfsdk/pwl/cpwl_stateful_button.h"

#include <utility>

CPWL_StatefulButton::CPWL_StatefulButton(
    const CreateParams& cp,
    std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData)
    : CPWL_Wnd(cp, std::move(pAttachedData)) {}

CPWL_StatefulButton::~CPWL_StatefulButton() = default;

bool CPWL_StatefulButton::OnLButtonDown(Mask<FWL_EVENTFLAG> nFlag,
                                        const CFX_PointF& point) {
  CPWL_Wnd::OnLButtonDown(nFlag, point);
  SetCapture();
  return true;
}

bool CPWL_StatefulButton::SetCheck(bool bCheck) {
  if (IsReadOnly())
    return false;

  m_bChecked = bCheck;
  return true;
}

CPWL_CheckBox::CPWL_CheckBox(
    const CreateParams& cp,
    std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData)
    : CPWL_StatefulButton(cp, std::move(pAttachedData)) {}

CPWL_CheckBox::~CPWL_CheckBox() = default;

bool CPWL_CheckBox::OnLButtonUp(Mask<FWL_EVENTFLAG> nFlag,
                                const CFX_PointF& point) {
  return SetCheck(!IsChecked());
}

bool CPWL_CheckBox::OnChar(uint16_t nChar, Mask<FWL_EVENTFLAG> nFlag) {
  return SetCheck(!IsChecked());
}

CPWL_RadioButton::CPWL_RadioButton(
    const CreateParams& cp,
    std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData)
    : CPWL_StatefulButton(cp, std::move(pAttachedData)) {}

CPWL_RadioButton::~CPWL_RadioButton() = default;

bool CPWL_RadioButton::OnLButtonUp(Mask<FWL_EVENTFLAG> nFlag,
                                   const CFX_PointF& point) {
  return SetCheck(true);
}

bool CPWL_RadioButton::OnChar(uint16_t nChar, Mask<FWL_EVENTFLAG> nFlag) {
  return SetCheck(true);
}
