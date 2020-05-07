// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_RENDEROPTIONS_H_
#define CORE_FXGE_CFX_RENDEROPTIONS_H_

#include <memory>

struct CFX_RenderOptions {
  CFX_RenderOptions();
  ~CFX_RenderOptions();

  void LoadTextFlags(uint32_t text_flags);

  // Optimize text rendering for LCD display.
  bool bClearType = false;

  // Disable anti aliasing for text rendering.
  bool bNoTextSmooth = false;
};

inline bool operator==(const CFX_RenderOptions& lhs,
                       const CFX_RenderOptions& rhs) {
  return lhs.bClearType == rhs.bClearType &&
         lhs.bNoTextSmooth == rhs.bNoTextSmooth;
}

inline bool operator!=(const CFX_RenderOptions& lhs,
                       const CFX_RenderOptions& rhs) {
  return !(lhs == rhs);
}

#endif  // CORE_FXGE_CFX_RENDEROPTIONS_H_
