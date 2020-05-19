// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_timer.h"

#include <map>

#include "third_party/base/no_destructor.h"

namespace {

using TimerMap = std::map<int32_t, CFX_Timer*>;
TimerMap& GetPWLTimerMap() {
  static pdfium::base::NoDestructor<TimerMap> timer_map;
  return *timer_map;
}

}  // namespace

CFX_Timer::CFX_Timer(TimerHandlerIface* pTimerHandler,
                     CallbackIface* pCallbackIface,
                     int32_t nInterval)
    : timer_id_(pTimerHandler->SetTimer(nInterval, TimerProc)),
      timer_handler_(pTimerHandler),
      callback_iface_(pCallbackIface) {
  ASSERT(callback_iface_);
  if (HasValidID())
    GetPWLTimerMap()[timer_id_] = this;
}

CFX_Timer::~CFX_Timer() {
  if (HasValidID()) {
    timer_handler_->KillTimer(timer_id_);
    GetPWLTimerMap().erase(timer_id_);
  }
}

// static
void CFX_Timer::TimerProc(int32_t idEvent) {
  auto it = GetPWLTimerMap().find(idEvent);
  if (it != GetPWLTimerMap().end())
    it->second->callback_iface_->OnTimerFired();
}
