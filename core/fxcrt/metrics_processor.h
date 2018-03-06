// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_METRICS_PROCESSOR_H_
#define CORE_FXCRT_METRICS_PROCESSOR_H_

#include <memory>
#include <utility>

#include "core/fxcrt/metrics_handler_iface.h"
#include "core/fxcrt/unowned_ptr.h"
#include "core/fxcrt/widestring.h"

namespace fxcrt {

class MetricsProcessor {
 public:
  static MetricsProcessor* GetInstance();
  static void Destroy();

  ~MetricsProcessor();

  void SetHandler(std::unique_ptr<MetricsHandlerIface> handler) {
    handler_ = std::move(handler);
  }

  void SendHistogram(WideString name,
                     uint32_t sample,
                     uint32_t min,
                     uint32_t max,
                     uint32_t num_buckets);
  void SendEnum(WideString name, uint32_t sample, uint32_t max);

 protected:
  MetricsProcessor();

  std::unique_ptr<MetricsHandlerIface> handler_;
};

}  // namespace fxcrt

using fxcrt::MetricsProcessor;

#endif  // CORE_FXCRT_METRICS_PROCESSOR_H_
