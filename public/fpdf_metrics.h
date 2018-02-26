// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_FPDF_METRICS_H_
#define PUBLIC_FPDF_METRICS_H_

struct FPDF_Metrics {
  // Callback for histogram metrics data.
  //
  // |name| is the name of the metric in UTF16-LE format.
  // |sample| is the value to be recorded (|min| <= |sample| < |max|)
  // |min| is the minimum value of the histogram samples (|min| > 0)
  // |max| is the maximum value of the histogram samples
  // |num_buckets| is the number of histogram buckets
  void (*SendHistogram)(FPDF_WIDESTRING name,
                        unsigned int min,
                        unsigned int max,
                        int num_buckets);

  // Callback to send linear histogram metrics data.
  //
  // |name| is the name of the metric in UTF16-LE format.
  // |sample| is the sample value to be recorded (1 <= |sample| < |max|)
  // |max| is the maxium value fo the histogram samples.
  void (*SendEnum)(FPDF_WIDESTRING name, unsigned int sample, unsigned int max);

  // Callback for sparse histogram metrics data.
  //
  // |name| the name of the metric in UTF16-LE format
  // |sample| the value to be recorded.
  void (*SendSparse)(FPDF_WIDESTRING name, int sample);

  // Callback to send an action.
  //
  // |name| the name of the action in UTF16-LE format.
  void (*SendAction)(FPDF_WIDESTRING name);
};
typedef struct FPDF_Metrics FPDF_Metrics;

void FPDF_SetMetricsHandler(FPDF_Metrics* handler);

#endif  // PUBLIC_FPDF_METRICS_H_
