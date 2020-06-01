// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_textrenderoptions.h"

CFX_TextRenderOptions::CFX_TextRenderOptions() = default;

CFX_TextRenderOptions::CFX_TextRenderOptions(
    const CFX_TextRenderOptions& other) = default;

CFX_TextRenderOptions::~CFX_TextRenderOptions() = default;

void CFX_TextRenderOptions::SetTextUseLcd(bool use_lcd) {
  if (edging_type < kLcd && use_lcd)
    edging_type = kLcd;
  if (edging_type >= kLcd && !use_lcd)
    edging_type = kAntiAliasing;
}
