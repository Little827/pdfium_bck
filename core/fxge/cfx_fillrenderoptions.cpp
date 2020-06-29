// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_fillrenderoptions.h"

#include "core/fxge/render_defines.h"
#include "third_party/base/no_destructor.h"

CFX_FillRenderOptions::CFX_FillRenderOptions() = default;

CFX_FillRenderOptions::CFX_FillRenderOptions(int fill_type)
    : fill_type(static_cast<CFX_FillRenderOptions::FillType>(fill_type)) {}

const CFX_FillRenderOptions GetFillRenderOptionsFromIntegerFlag(int flags) {
  CFX_FillRenderOptions options(flags & 3);
  if (flags & FXFILL_FULLCOVER)
    options.is_full_cover = true;
  if (flags & FXFILL_NOPATHSMOOTH)
    options.is_path_aliased = true;
  if (flags & FXFILL_RECT_AA)
    options.is_rect_aa = true;
  if (flags & FX_FILL_STROKE)
    options.is_stroke = true;
  if (flags & FX_FILL_TEXT_MODE)
    options.is_text_mode = true;
  if (flags & FX_ZEROAREA_FILL)
    options.is_zero_area = true;
  if (flags & FX_STROKE_ADJUST)
    options.stroke_adjust = true;
  if (flags & FX_STROKE_TEXT_MODE)
    options.stroke_text_mode = true;
  return options;
}

int GetIntegerFlagFromFillRenderOptions(const CFX_FillRenderOptions& options) {
  int flags = static_cast<int>(options.fill_type);
  if (options.is_full_cover)
    flags |= FXFILL_FULLCOVER;
  if (options.is_path_aliased)
    flags |= FXFILL_NOPATHSMOOTH;
  if (options.is_rect_aa)
    flags |= FXFILL_RECT_AA;
  if (options.is_stroke)
    flags |= FX_FILL_STROKE;
  if (options.is_text_mode)
    flags |= FX_FILL_TEXT_MODE;
  if (options.is_zero_area)
    flags |= FX_ZEROAREA_FILL;
  if (options.stroke_adjust)
    flags |= FX_STROKE_ADJUST;
  if (options.stroke_text_mode)
    flags |= FX_STROKE_TEXT_MODE;
  return flags;
}
