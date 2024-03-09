// Copyright 2019 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_DIB_CFX_CMYK_TO_SRGB_H_
#define CORE_FXGE_DIB_CFX_CMYK_TO_SRGB_H_

#include <stdint.h>

#include <array>

namespace fxge {

std::array<float, 3> AdobeCMYK_to_sRGB(float c, float m, float y, float k);
std::array<uint8_t, 3> AdobeCMYK_to_sRGB1(uint8_t c,
                                          uint8_t m,
                                          uint8_t y,
                                          uint8_t k);

}  // namespace fxge

using fxge::AdobeCMYK_to_sRGB;
using fxge::AdobeCMYK_to_sRGB1;

#endif  // CORE_FXGE_DIB_CFX_CMYK_TO_SRGB_H_
