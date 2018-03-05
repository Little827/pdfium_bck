// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "public/fpdf_metrics.h"

#include "core/fxcrt/bytestring.h"
#include "core/fxcrt/ifx_metrics_handler.h"
#include "core/fxcrt/metrics_processor.h"
#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/ptr_util.h"

namespace {

// NOTE: |bsUTF16LE| must outlive the use of the result. Care must be taken
// since modifying the result would impact |bsUTF16LE|.
FPDF_WIDESTRING AsFPDFWideString(ByteString bsUTF16LE) {
  return reinterpret_cast<FPDF_WIDESTRING>(
      bsUTF16LE.GetBuffer(bsUTF16LE.GetLength()));
}

class MetricsProxy : public IFX_MetricsHandler {
 public:
  explicit MetricsProxy(FPDF_MetricsHandler* handler)
      : IFX_MetricsHandler(), handler_(handler) {
    ASSERT(handler_);
  }
  ~MetricsProxy() override = default;

  void SendHistogram(WideString name,
                     uint32_t sample,
                     uint32_t min,
                     uint32_t max,
                     uint32_t num_buckets) override {
    if (!handler_->SendHistogram)
      return;

    handler_->SendHistogram(handler_.Get(),
                            AsFPDFWideString(name.UTF16LE_Encode()), sample,
                            min, max, num_buckets);
  }

  void SendEnum(WideString name, uint32_t sample, uint32_t max) override {
    if (!handler_->SendEnum)
      return;

    handler_->SendEnum(handler_.Get(), AsFPDFWideString(name.UTF16LE_Encode()),
                       sample, max);
  }

  void SendAction(WideString action) override {
    if (!handler_->SendAction)
      return;

    handler_->SendAction(handler_.Get(),
                         AsFPDFWideString(action.UTF16LE_Encode()));
  }

 private:
  UnownedPtr<FPDF_MetricsHandler> handler_;
};

}  // namespace

FPDF_EXPORT void FPDF_CALLCONV
FPDF_SetMetricsHandler(FPDF_MetricsHandler* handler) {
  if (!handler) {
    MetricsProcessor::Instance()->SetHandler(nullptr);
    return;
  }

  MetricsProcessor::Instance()->SetHandler(
      pdfium::MakeUnique<MetricsProxy>(handler));
}
