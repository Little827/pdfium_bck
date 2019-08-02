// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FPDFSDK_CFX_SYSTEMHANDLER_H_
#define FPDFSDK_CFX_SYSTEMHANDLER_H_

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_string.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/unowned_ptr.h"

class CFFL_FormFiller;
class CPDF_Document;
class CPDFSDK_FormFillEnvironment;
class CPDFSDK_Widget;

class CFX_SystemHandler final : public FXSYS_TimerIface {
 public:
  explicit CFX_SystemHandler(CPDFSDK_FormFillEnvironment* pFormFillEnv);
  ~CFX_SystemHandler() override;

  // FXSYS_TimerIface:
  int32_t SetTimer(int32_t uElapse, TimerCallback lpTimerFunc) override;
  void KillTimer(int32_t nID) override;

  void InvalidateRect(CPDFSDK_Widget* widget, const CFX_FloatRect& rect);
  void OutputSelectedRect(CFFL_FormFiller* pFormFiller,
                          const CFX_FloatRect& rect);
  bool IsSelectionImplemented() const;
  void SetCursor(int32_t nCursorType);

 private:
  UnownedPtr<CPDFSDK_FormFillEnvironment> const m_pFormFillEnv;
};

#endif  // FPDFSDK_CFX_SYSTEMHANDLER_H_
