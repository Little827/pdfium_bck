// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_graphstatedata.h"

#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_system.h"

CFX_GraphStateData::CFX_GraphStateData()
    : m_LineCap(LineCapButt),
      m_DashCount(0),
      m_DashPhase(0),
      m_LineJoin(LineJoinMiter),
      m_MiterLimit(10 * 1.0f),
      m_LineWidth(1.0f) {}

CFX_GraphStateData::CFX_GraphStateData(const CFX_GraphStateData& src) {
  Copy(src);
}

void CFX_GraphStateData::Copy(const CFX_GraphStateData& src) {
  m_LineCap = src.m_LineCap;
  m_DashCount = src.m_DashCount;
  m_DashPhase = src.m_DashPhase;
  m_LineJoin = src.m_LineJoin;
  m_MiterLimit = src.m_MiterLimit;
  m_LineWidth = src.m_LineWidth;
  if (m_DashCount) {
    m_DashArray.reset(FX_Alloc(float, m_DashCount));
    memcpy(m_DashArray.get(), src.m_DashArray.get(),
           m_DashCount * sizeof(float));
  } else {
    m_DashArray.reset();
  }
}

CFX_GraphStateData::~CFX_GraphStateData() = default;

void CFX_GraphStateData::SetDashCount(int count) {
  m_DashCount = count;
  if (count)
    m_DashArray.reset(FX_Alloc(float, count));
  else
    m_DashArray.reset();
}
