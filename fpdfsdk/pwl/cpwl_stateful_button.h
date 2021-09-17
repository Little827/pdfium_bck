// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FPDFSDK_PWL_CPWL_STATEFUL_BUTTON_H_
#define FPDFSDK_PWL_CPWL_STATEFUL_BUTTON_H_

#include <memory>

#include "fpdfsdk/pwl/cpwl_pushbutton.h"

class CPWL_StatefulButton : public CPWL_Wnd {
 public:
  CPWL_StatefulButton(
      const CreateParams& cp,
      std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData);
  ~CPWL_StatefulButton() override;

  // CPWL_Wnd:
  bool OnLButtonDown(Mask<FWL_EVENTFLAG> nFlag,
                     const CFX_PointF& point) override;

  bool IsChecked() const { return m_bChecked; }
  bool SetCheck(bool bCheck);

 private:
  bool m_bChecked = false;
};

class CPWL_CheckBox final : public CPWL_StatefulButton {
 public:
  CPWL_CheckBox(
      const CreateParams& cp,
      std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData);
  ~CPWL_CheckBox() override;

  // CPWL_StatefulButton:
  bool OnLButtonUp(Mask<FWL_EVENTFLAG> nFlag, const CFX_PointF& point) override;
  bool OnChar(uint16_t nChar, Mask<FWL_EVENTFLAG> nFlag) override;
};

class CPWL_RadioButton final : public CPWL_StatefulButton {
 public:
  CPWL_RadioButton(
      const CreateParams& cp,
      std::unique_ptr<IPWL_SystemHandler::PerWindowData> pAttachedData);
  ~CPWL_RadioButton() override;

  // CPWL_StatefulButton:
  bool OnLButtonUp(Mask<FWL_EVENTFLAG> nFlag, const CFX_PointF& point) override;
  bool OnChar(uint16_t nChar, Mask<FWL_EVENTFLAG> nFlag) override;
};

#endif  // FPDFSDK_PWL_CPWL_STATEFUL_BUTTON_H_
