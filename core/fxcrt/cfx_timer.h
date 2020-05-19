// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_TIMER_H_
#define CORE_FXCRT_CFX_TIMER_H_

#include "core/fxcrt/timerhandler_iface.h"
#include "core/fxcrt/unowned_ptr.h"

class CFX_TimerHandler;

class CFX_Timer {
 public:
  class CallbackIface {
   public:
    virtual ~CallbackIface() = default;
    virtual void OnTimerFired() = 0;
  };

  CFX_Timer(TimerHandlerIface* pTimerHandler,
            CallbackIface* pCallbackIface,
            int32_t nInterval);
  ~CFX_Timer();

  bool HasValidID() const {
    return timer_id_ != TimerHandlerIface::kInvalidTimerID;
  }

 private:
  static void TimerProc(int32_t idEvent);

  const int32_t timer_id_;
  UnownedPtr<TimerHandlerIface> const timer_handler_;
  UnownedPtr<CallbackIface> const callback_iface_;
};

#endif  // CORE_FXCRT_CFX_TIMER_H_
