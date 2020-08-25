// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_fillrenderoptions.h"

// static
const CFX_FillRenderOptions& CFX_FillRenderOptions::EvenOddOptions() {
  static constexpr CFX_FillRenderOptions kEvenOdd(
      CFX_FillRenderOptions::FillType::kEvenOdd);
  return kEvenOdd;
}

// static
const CFX_FillRenderOptions& CFX_FillRenderOptions::WindingOptions() {
  static constexpr CFX_FillRenderOptions kWinding(
      CFX_FillRenderOptions::FillType::kWinding);
  return kWinding;
}
