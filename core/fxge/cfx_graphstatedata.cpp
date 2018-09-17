// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/cfx_graphstatedata.h"

#include "core/fxcrt/fx_memory.h"
#include "core/fxcrt/fx_system.h"

CFX_GraphStateData::CFX_GraphStateData() = default;

CFX_GraphStateData::CFX_GraphStateData(const CFX_GraphStateData& src) = default;

CFX_GraphStateData::~CFX_GraphStateData() = default;

CFX_GraphStateData& CFX_GraphStateData::operator=(
    const CFX_GraphStateData& that) = default;

void CFX_GraphStateData::SetDashCount(size_t count) {
  m_DashArray.resize(count);
}
