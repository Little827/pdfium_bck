// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_fillrenderoptions.h"

#include "core/fxge/render_defines.h"
#include "third_party/base/no_destructor.h"

// static
const CFX_FillRenderOptions& CFX_FillRenderOptions::AlternateOptions() {
  static pdfium::base::NoDestructor<CFX_FillRenderOptions> alternate_options(
      FXFILL_ALTERNATE);
  return *alternate_options;
}

// static
const CFX_FillRenderOptions& CFX_FillRenderOptions::WindingOptions() {
  static pdfium::base::NoDestructor<CFX_FillRenderOptions> winding_options(
      FXFILL_WINDING);
  return *winding_options;
}

CFX_FillRenderOptions::CFX_FillRenderOptions() = default;

CFX_FillRenderOptions::CFX_FillRenderOptions(int fill_mode)
    : fill_type(fill_mode) {}
