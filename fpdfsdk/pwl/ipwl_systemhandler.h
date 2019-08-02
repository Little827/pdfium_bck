// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FPDFSDK_PWL_IPWL_SYSTEMHANDLER_H_
#define FPDFSDK_PWL_IPWL_SYSTEMHANDLER_H_

#include "core/fxcrt/fx_coordinates.h"
#include "core/fxcrt/fx_system.h"

class CPDFSDK_FormFillEnvironment;
class CPDFSDK_Widget;
class CFFL_FormFiller;

class IPWL_SystemHandler {
 public:
  static constexpr int32_t kInvalidTimerID = 0;
  using TimerCallback = void (*)(int32_t idEvent);

  virtual ~IPWL_SystemHandler() = default;

  virtual void InvalidateRect(CPDFSDK_Widget* widget,
                              const CFX_FloatRect& rect) = 0;
  virtual void OutputSelectedRect(CFFL_FormFiller* pFormFiller,
                                  const CFX_FloatRect& rect) = 0;
  virtual bool IsSelectionImplemented() const = 0;
  virtual void SetCursor(int32_t nCursorType) = 0;
  virtual int32_t SetTimer(int32_t uElapse, TimerCallback lpTimerFunc) = 0;
  virtual void KillTimer(int32_t nID) = 0;
};

#endif  // FPDFSDK_PWL_IPWL_SYSTEMHANDLER_H_
