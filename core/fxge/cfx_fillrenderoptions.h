// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
#define CORE_FXGE_CFX_FILLRENDEROPTIONS_H_

#include "core/fxge/render_defines.h"

struct CFX_FillRenderOptions {
  enum class FillType {
    kNoFill = 0,
    kAlternate = FXFILL_ALTERNATE,
    kWinding = FXFILL_WINDING,
  };

  CFX_FillRenderOptions();
  explicit CFX_FillRenderOptions(int fill_type);

  // Fill type.
  FillType fill_type = FillType::kNoFill;

  // Fills with the sum of colors from both cover and source.
  bool is_full_cover = false;

  // Whether anti aliasing is enabled for path rendering.
  bool is_path_aliased = false;

  // Rect paths use anti-aliasing.
  bool is_rect_aa = false;

  // Path is stroke.
  bool is_stroke = false;

  // Path is text.
  bool is_text_mode = false;

  // Path covers zero area.
  bool is_zero_area = false;

  // Adjusted stroke rendering is enabled.
  bool stroke_adjust = false;

  // Renders text by filling strokes.
  bool stroke_text_mode = false;
};

// TODO(crbug.com/pdfium/1531): Remove this function once all integer rendering
// flags are replaced with CFX_FillRenderOptions.
// Generates a matching CFX_FillRenderOptions struct from integer |flags|
// which contains fill rendering options.
const CFX_FillRenderOptions GetFillRenderOptionsFromIntegerFlag(int flags);

// TODO(crbug.com/pdfium/1531): Remove this function once all integer rendering
// flags are replaced with CFX_FillRenderOptions.
// Generates a integer which represents fill options from CFX_FillRenderOptions
// struct |options|.
int GetIntegerFlagFromFillRenderOptions(const CFX_FillRenderOptions& options);

#endif  // CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
