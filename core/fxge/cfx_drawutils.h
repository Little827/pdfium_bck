// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_CFX_DRAWUTILS_H_
#define CORE_FXGE_CFX_DRAWUTILS_H_

class CFX_RenderDevice;
class CFX_Matrix;
class CFX_FloatRect;

class CFX_DrawUtils {
 public:
  CFX_DrawUtils();
  ~CFX_DrawUtils();

  void DrawFocusRect(CFX_RenderDevice* render_device,
                     const CFX_Matrix& mtUser2Device,
                     const CFX_FloatRect& view_bounding_box);
};
#endif  // CORE_FXGE_CFX_DRAWUTILS_H_
