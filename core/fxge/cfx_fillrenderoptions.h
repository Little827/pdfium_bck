// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
#define CORE_FXGE_CFX_FILLRENDEROPTIONS_H_

struct CFX_FillRenderOptions {
  static const CFX_FillRenderOptions& WindingOptions();
  static const CFX_FillRenderOptions& AlternateOptions();

  CFX_FillRenderOptions();
  explicit CFX_FillRenderOptions(int fill_type);

  inline bool operator==(const CFX_FillRenderOptions& other) const {
    return is_rect_aa == other.is_rect_aa &&
           is_full_cover == other.is_full_cover &&
           is_stroke == other.is_stroke && is_text_mode == other.is_text_mode &&
           is_zero_area == other.is_zero_area &&
           is_path_aliased == other.is_path_aliased &&
           stroke_adjust == other.stroke_adjust &&
           stroke_text_mode == other.stroke_text_mode &&
           fill_type == other.fill_type;
  }

  inline bool operator!=(const CFX_FillRenderOptions& other) const {
    return !(*this == other);
  }

  // Rect path uses anti-aliasing
  bool is_rect_aa = false;

  // Fills with the sum of colors of cover and source.
  bool is_full_cover = false;

  // Path is stroke.
  bool is_stroke = false;

  // Path is text. // only affect Windows.
  bool is_text_mode = false;

  // Path covers zero area.
  bool is_zero_area = false;

  // Whether anti aliasing is enabled for path rendering.
  bool is_path_aliased = false;

  // Adjusted stroke rendering is enabled.
  bool stroke_adjust = false;

  // Renders text by filling strokes.
  bool stroke_text_mode = false;

  // Fill type. The value can be 0 (for not filled), FXFILL_WINDING or
  // FXFILL_ALTERNATE.
  int fill_type = 0;
};

#endif  // CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
