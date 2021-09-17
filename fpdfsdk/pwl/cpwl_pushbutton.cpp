// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "fpdfsdk/pwl/cpwl_pushbutton.h"

#include <utility>

CPWL_PushButton::CPWL_PushButton(
    const CreateParams& cp,
    std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData)
    : CPWL_Wnd(cp, std::move(pAttachedData)) {
  GetCreationParams()->eCursorType = IPWL_SystemHandler::CursorStyle::kHand;
}

CPWL_PushButton::~CPWL_PushButton() = default;

bool CPWL_PushButton::OnLButtonDown(Mask<FWL_EVENTFLAG> nFlag,
                                    const CFX_PointF& point) {
  CPWL_Wnd::OnLButtonDown(nFlag, point);
  SetCapture();
  return true;
}

bool CPWL_PushButton::OnLButtonUp(Mask<FWL_EVENTFLAG> nFlag,
                                  const CFX_PointF& point) {
  CPWL_Wnd::OnLButtonUp(nFlag, point);
  ReleaseCapture();
  return true;
}

CFX_FloatRect CPWL_PushButton::GetFocusRect() const {
  return GetWindowRect().GetDeflated(static_cast<float>(GetBorderWidth()),
                                     static_cast<float>(GetBorderWidth()));
}
