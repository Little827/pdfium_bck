// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_renderoptions.h"

#include <memory>

#include "core/fxge/render_defines.h"

CFX_RenderOptions::CFX_RenderOptions() = default;

CFX_RenderOptions::~CFX_RenderOptions() = default;

void CFX_RenderOptions::InitializeFromTextFlags(uint32_t text_flags) {
  if (!text_flags)
    return;

  bNoTextSmooth = !!(text_flags & FXTEXT_NOSMOOTH);

  // LCD optimization can only be enabled when anti aliasing is enabled.
  bClearType = !bNoTextSmooth && (text_flags & FXTEXT_CLEARTYPE);
}
