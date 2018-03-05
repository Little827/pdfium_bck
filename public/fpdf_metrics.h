// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_FPDF_METRICS_H_
#define PUBLIC_FPDF_METRICS_H_

#include "public/fpdfview.h"

// Exported Functions
#ifdef __cplusplus
extern "C" {
#endif

struct FPDF_MetricsHandler_ {
  // Callback for histogram metrics data.
  //
  // |name| is the name of the metric in UTF16-LE format.
  // |sample| is the value to be recorded (|min| <= |sample| < |max|)
  // |min| is the minimum value of the histogram samples (|min| > 0)
  // |max| is the maximum value of the histogram samples
  // |num_buckets| is the number of histogram buckets
  void (*SendHistogram)(struct FPDF_MetricsHandler_* handler,
                        FPDF_WIDESTRING name,
                        unsigned int sample,
                        unsigned int min,
                        unsigned int max,
                        unsigned int num_buckets);

  // Callback to send linear histogram metrics data.
  //
  // |name| is the name of the metric in UTF16-LE format.
  // |sample| is the sample value to be recorded (1 <= |sample| < |max|)
  // |max| is the maxium value fo the histogram samples.
  void (*SendEnum)(struct FPDF_MetricsHandler_* handler,
                   FPDF_WIDESTRING name,
                   unsigned int sample,
                   unsigned int max);
};
typedef struct FPDF_MetricsHandler_ FPDF_MetricsHandler;

// Set the metrics handler for the system. This |handler| must remain valid
// until the PDFium library is shutdown with |FPDF_DestroyLibrary|.
FPDF_EXPORT void FPDF_CALLCONV
FPDF_SetMetricsHandler(FPDF_MetricsHandler* handler);

#ifdef __cplusplus
}
#endif

#endif  // PUBLIC_FPDF_METRICS_H_
