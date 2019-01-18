// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef XFA_FXGRAPHICS_CXFA_GRAPHICS_H_
#define XFA_FXGRAPHICS_CXFA_GRAPHICS_H_

#include <memory>
#include <vector>

#include "core/fxcrt/fx_system.h"
#include "core/fxge/cfx_graphstatedata.h"
#include "xfa/fxgraphics/cxfa_gecolor.h"

using FX_FillMode = int32_t;

enum class FX_HatchStyle {
  Horizontal = 0,
  Vertical = 1,
  ForwardDiagonal = 2,
  BackwardDiagonal = 3,
  Cross = 4,
  DiagonalCross = 5
};

class CFX_DIBBase;
class CFX_RenderDevice;
class CXFA_GEPath;

class CXFA_Graphics {
 public:
  // |pRenderDevice| may be null for a non-device-based context.
  explicit CXFA_Graphics(CFX_RenderDevice* pRenderDevice);
  ~CXFA_Graphics();

  void SaveGraphState();
  void RestoreGraphState();

  CFX_RectF GetClipRect() const;
  const CFX_Matrix* GetMatrix() const;
  CFX_RenderDevice* GetRenderDeviceIfPresent() const;

  void SetLineCap(CFX_GraphStateData::LineCap lineCap);
  void SetLineDash(float dashPhase, const float* dashArray, size_t dashCount);
  void SetSolidLineDash();
  void SetLineWidth(float lineWidth);
  void EnableActOnDash();
  void SetStrokeColor(const CXFA_GEColor& color);
  void SetFillColor(const CXFA_GEColor& color);
  void SetClipRect(const CFX_RectF& rect);
  void StrokePath(CXFA_GEPath* path, const CFX_Matrix* matrix);
  void FillPath(CXFA_GEPath* path,
                FX_FillMode fillMode,
                const CFX_Matrix* matrix);
  void ConcatMatrix(const CFX_Matrix* matrix);

 private:
  struct TInfo {
    TInfo();
    explicit TInfo(const TInfo& info);
    TInfo& operator=(const TInfo& other);

    CFX_GraphStateData graphState;
    CFX_Matrix CTM;
    bool isActOnDash;
    CXFA_GEColor strokeColor;
    CXFA_GEColor fillColor;
  };

  void RenderDeviceStrokePath(const CXFA_GEPath* path,
                              const CFX_Matrix* matrix);
  void RenderDeviceFillPath(const CXFA_GEPath* path,
                            FX_FillMode fillMode,
                            const CFX_Matrix* matrix);
  void FillPathWithPattern(const CXFA_GEPath* path,
                           FX_FillMode fillMode,
                           const CFX_Matrix& matrix);
  void FillPathWithShading(const CXFA_GEPath* path,
                           FX_FillMode fillMode,
                           const CFX_Matrix& matrix);
  void SetDIBitsWithMatrix(const RetainPtr<CFX_DIBBase>& source,
                           const CFX_Matrix& matrix);

  CFX_RenderDevice* const m_pRenderDevice;  // Not owned, may be null.
  TInfo m_info;
  std::vector<std::unique_ptr<TInfo>> m_infoStack;
};

#endif  // XFA_FXGRAPHICS_CXFA_GRAPHICS_H_
