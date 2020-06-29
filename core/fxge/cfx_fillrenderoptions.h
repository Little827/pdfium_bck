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

  static const CFX_FillRenderOptions& WindingOptions();
  static const CFX_FillRenderOptions& AlternateOptions();

  CFX_FillRenderOptions();
  explicit CFX_FillRenderOptions(int fill_type);

  inline bool operator==(const CFX_FillRenderOptions& other) const {
    return fill_type == other.fill_type &&
           is_full_cover == other.is_full_cover &&
           is_path_aliased == other.is_path_aliased &&
           is_rect_aa == other.is_rect_aa && is_stroke == other.is_stroke &&
           is_text_mode == other.is_text_mode &&
           is_zero_area == other.is_zero_area &&
           stroke_adjust == other.stroke_adjust &&
           stroke_text_mode == other.stroke_text_mode;
  }

  inline bool operator!=(const CFX_FillRenderOptions& other) const {
    return !(*this == other);
  }

  // Fill type.
  FillType fill_type = FillType::kNoFill;

  // Fills with the sum of colors of cover and source.
  bool is_full_cover = false;

  // Whether anti aliasing is enabled for path rendering.
  bool is_path_aliased = false;

  // Rect path uses anti-aliasing
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

// Generates a matching CFX_FillRenderOptions struct from integer |flags|
// which contains fill rendering options.
const CFX_FillRenderOptions GetFillRenderOptionsFromIntegerFlag(int flags);

// Generates a integer which represents fill options from CFX_FillRenderOptions
// struct |options|.
int GetIntegerFlagFromFillRenderOptions(const CFX_FillRenderOptions& options);

#endif  // CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
