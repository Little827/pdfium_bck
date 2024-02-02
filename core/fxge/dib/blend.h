// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_DIB_BLEND_H_
#define CORE_FXGE_DIB_BLEND_H_

#include "third_party/base/numerics/safe_conversions.h"

enum class BlendMode;

namespace fxge {

// Note that Blend() only handles separable blend modes.
int Blend(BlendMode blend_mode,
          pdfium::base::StrictNumeric<uint8_t> strict_back_color,
          pdfium::base::StrictNumeric<uint8_t> strict_src_color);

}  // namespace fxge

#endif  // CORE_FXGE_DIB_BLEND_H_
