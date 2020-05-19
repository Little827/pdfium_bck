// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_renderoptions.h"

CFX_RenderOptions::TextOptions::TextOptions() = default;

CFX_RenderOptions::TextOptions::~TextOptions() = default;

CFX_RenderOptions::FontOptions::FontOptions() = default;

CFX_RenderOptions::FontOptions::~FontOptions() = default;

CFX_RenderOptions::CFX_RenderOptions() = default;

CFX_RenderOptions::~CFX_RenderOptions() = default;

void CFX_RenderOptions::SetTextUseLcd(bool use_lcd) {
  text_options_.use_lcd = use_lcd;
}
