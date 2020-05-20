// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_renderoptions.h"

CFX_RenderOptions::TextOptions::TextOptions() = default;

CFX_RenderOptions::TextOptions::~TextOptions() = default;

CFX_RenderOptions::FontOptions::FontOptions() = default;

CFX_RenderOptions::FontOptions::~FontOptions() = default;

CFX_RenderOptions::CFX_RenderOptions() = default;

CFX_RenderOptions::CFX_RenderOptions(const CFX_RenderOptions& other) = default;

CFX_RenderOptions::~CFX_RenderOptions() = default;

void CFX_RenderOptions::SetTextUseLcd(bool is_lcd) {
  text_options_.is_lcd = is_lcd;
}
