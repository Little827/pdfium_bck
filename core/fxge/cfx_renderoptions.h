// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_RENDEROPTIONS_H_
#define CORE_FXGE_CFX_RENDEROPTIONS_H_

#include <memory>

struct CFX_RenderOptions {
  CFX_RenderOptions();
  ~CFX_RenderOptions();

  void InitializeFromTextFlags(uint32_t text_flags);

  // Use anti aliasing for text rendering.
  bool text_is_smooth = true;

  // Optimize text rendering for LCD display.
  bool text_use_lcd = false;
};

inline bool operator==(const CFX_RenderOptions& lhs,
                       const CFX_RenderOptions& rhs) {
  return lhs.text_is_smooth == rhs.text_is_smooth &&
         lhs.text_use_lcd == rhs.text_use_lcd;
}

inline bool operator!=(const CFX_RenderOptions& lhs,
                       const CFX_RenderOptions& rhs) {
  return !(lhs == rhs);
}

#endif  // CORE_FXGE_CFX_RENDEROPTIONS_H_
