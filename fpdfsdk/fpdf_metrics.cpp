// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_metrics.h"

#include "core/fxcrt/metrics_handler_iface.h"
#include "core/fxcrt/metrics_processor.h"
#include "core/fxcrt/unowned_ptr.h"
#include "fpdfsdk/fpdf_string.h"
#include "third_party/base/ptr_util.h"

namespace {

class MetricsHandler : public MetricsHandlerIface {
 public:
  explicit MetricsHandler(FPDF_MetricsHandler* handler) : handler_(handler) {
    ASSERT(handler_);
  }
  ~MetricsHandler() override = default;

  void SendHistogram(WideString name,
                     uint32_t sample,
                     uint32_t min,
                     uint32_t max,
                     uint32_t num_buckets) override {
    if (!handler_->SendHistogram)
      return;

    ByteString bs_name = name.UTF16LE_Encode();
    handler_->SendHistogram(handler_.Get(), AsFPDFWideString(&bs_name), sample,
                            min, max, num_buckets);
  }

  void SendEnum(WideString name, uint32_t sample, uint32_t max) override {
    if (!handler_->SendEnum)
      return;

    ByteString bs_name = name.UTF16LE_Encode();
    handler_->SendEnum(handler_.Get(), AsFPDFWideString(&bs_name), sample, max);
  }

 private:
  UnownedPtr<FPDF_MetricsHandler> handler_;
};

}  // namespace

FPDF_EXPORT void FPDF_CALLCONV
FPDF_SetMetricsHandler(FPDF_MetricsHandler* handler) {
  if (!handler) {
    MetricsProcessor::GetInstance()->SetHandler(nullptr);
    return;
  }

  MetricsProcessor::GetInstance()->SetHandler(
      pdfium::MakeUnique<MetricsHandler>(handler));
}
