// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_IFX_METRICS_HANDLER_H_
#define CORE_FXCRT_IFX_METRICS_HANDLER_H_

#include "core/fxcrt/widestring.h"

class IFX_MetricsHandler {
 public:
  virtual ~IFX_MetricsHandler() = default;

  virtual void SendHistogram(WideString name,
                             uint32_t sample,
                             uint32_t min,
                             uint32_t max,
                             uint32_t num_buckets) = 0;
  virtual void SendEnum(WideString name, uint32_t sample, uint32_t max) = 0;
  virtual void SendAction(WideString action) = 0;

 protected:
  IFX_MetricsHandler() = default;
};

#endif  // CORE_FXCRT_IFX_METRICS_HANDLER_H_
