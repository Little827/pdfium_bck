// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_METRICS_HANDLER_IFACE_H_
#define CORE_FXCRT_METRICS_HANDLER_IFACE_H_

#include "core/fxcrt/widestring.h"

class MetricsHandlerIface {
 public:
  virtual ~MetricsHandlerIface() = default;

  virtual void SendHistogram(const WideString& name,
                             uint32_t sample,
                             uint32_t min,
                             uint32_t max,
                             uint32_t num_buckets) = 0;
  virtual void SendEnum(const WideString& name,
                        uint32_t sample,
                        uint32_t max) = 0;
};

#endif  // CORE_FXCRT_METRICS_HANDLER_IFACE_H_
