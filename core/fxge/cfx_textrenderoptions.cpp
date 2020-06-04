// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_textrenderoptions.h"

CFX_TextRenderOptions::CFX_TextRenderOptions()
    : font_is_cid(false), native_text(true), edging_type(kAntiAliasing) {}

CFX_TextRenderOptions::CFX_TextRenderOptions(
    const CFX_TextRenderOptions& other) = default;

CFX_TextRenderOptions::~CFX_TextRenderOptions() = default;

void CFX_TextRenderOptions::EnableLcd() {
  if (edging_type < kLcd)
    edging_type = kLcd;
}
