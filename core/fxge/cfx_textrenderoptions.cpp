// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/cfx_textrenderoptions.h"

// static
const CFX_TextRenderOptions& CFX_TextRenderOptions::LcdOptions() {
  static constexpr CFX_TextRenderOptions kInstance(kLcd);
  return kInstance;
}
