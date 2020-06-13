// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_textrenderoptions.h"

// static
const CFX_TextRenderOptions CFX_TextRenderOptions::LcdOptions() {
  return CFX_TextRenderOptions(kLcd);
}

CFX_TextRenderOptions::CFX_TextRenderOptions() = default;

CFX_TextRenderOptions::CFX_TextRenderOptions(AliasingType type)
    : aliasing_type(type) {}

CFX_TextRenderOptions::CFX_TextRenderOptions(
    const CFX_TextRenderOptions& other) = default;

CFX_TextRenderOptions::~CFX_TextRenderOptions() = default;

bool CFX_TextRenderOptions::IsSmooth() const {
  return aliasing_type >= kAntiAliasing;
}
