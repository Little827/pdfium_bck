// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_fillrenderoptions.h"

CFX_FillRenderOptions::CFX_FillRenderOptions() = default;

CFX_FillRenderOptions::CFX_FillRenderOptions(
    const CFX_FillRenderOptions& other) = default;

CFX_FillRenderOptions::CFX_FillRenderOptions(int fill_mode)
    : fill_type(fill_mode) {}

CFX_FillRenderOptions::~CFX_FillRenderOptions() = default;

bool CFX_FillRenderOptions::operator==(const CFX_FillRenderOptions& other) {
  return fill_rect_aa == other.fill_rect_aa &&
         fill_full_cover == other.fill_full_cover &&
         fill_stroke == other.fill_stroke &&
         fill_text_mode == other.fill_text_mode &&
         fill_zero_area == other.fill_zero_area &&
         no_path_smooth == other.no_path_smooth &&
         stroke_adjust == other.stroke_adjust &&
         stroke_text_mode == other.stroke_text_mode &&
         fill_type == other.fill_type;
}

bool CFX_FillRenderOptions::operator!=(const CFX_FillRenderOptions& other) {
  return !(*this == other);
}
