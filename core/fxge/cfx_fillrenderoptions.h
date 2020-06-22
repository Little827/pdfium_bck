// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
#define CORE_FXGE_CFX_FILLRENDEROPTIONS_H_

struct CFX_FillRenderOptions {
  static const CFX_FillRenderOptions& WindingOptions();
  static const CFX_FillRenderOptions& AlternateOptions();

  CFX_FillRenderOptions();
  CFX_FillRenderOptions(const CFX_FillRenderOptions& other);
  explicit CFX_FillRenderOptions(int fill_type);
  ~CFX_FillRenderOptions();

  bool IsDefault() const;

  bool fill_rect_aa = false;

  bool fill_full_cover = false;

  bool fill_stroke = false;

  bool fill_text_mode = false;

  bool fill_zero_area = false;

  bool is_path_smooth = true;

  bool stroke_adjust = false;

  bool stroke_text_mode = false;

  // Fill type. The value can be 0 (for not filled), FXFILL_WINDING or
  // FXFILL_ALTERNATE.
  int fill_type = 0;
};

#endif  // CORE_FXGE_CFX_FILLRENDEROPTIONS_H_
