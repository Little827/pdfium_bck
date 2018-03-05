// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/metrics_processor.h"

#include "core/fxcrt/bytestring.h"

namespace fxcrt {
namespace {

MetricsProcessor* g_metrics_processor_ = nullptr;

}  // namespace

// static
MetricsProcessor* MetricsProcessor::Instance() {
  if (g_metrics_processor_)
    return g_metrics_processor_;

  g_metrics_processor_ = new MetricsProcessor();
  return g_metrics_processor_;
}

// static
void MetricsProcessor::Destroy() {
  delete g_metrics_processor_;
  g_metrics_processor_ = nullptr;
}

MetricsProcessor::MetricsProcessor() = default;

MetricsProcessor::~MetricsProcessor() = default;

void MetricsProcessor::SendHistogram(WideString name,
                                     uint32_t sample,
                                     uint32_t min,
                                     uint32_t max,
                                     uint32_t num_buckets) {
  if (!handler_)
    return;
  handler_->SendHistogram(name, sample, min, max, num_buckets);
}

void MetricsProcessor::SendEnum(WideString name,
                                uint32_t sample,
                                uint32_t max) {
  if (!handler_)
    return;
  handler_->SendEnum(name, sample, max);
}

}  // namespace fxcrt
