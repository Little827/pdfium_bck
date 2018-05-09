// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/render/cpdf_transparency.h"

namespace {

constexpr int kGroup = 1 << 0;
constexpr int kIsolated = 1 << 1;

}  // namespace

CPDF_Transparency::CPDF_Transparency() {}

bool CPDF_Transparency::IsGroup() const {
  return !!(m_iTransparency & kGroup);
}

bool CPDF_Transparency::IsIsolated() const {
  return !!(m_iTransparency & kIsolated);
}

void CPDF_Transparency::SetGroup() {
  m_iTransparency |= kGroup;
}

void CPDF_Transparency::SetIsolated() {
  m_iTransparency |= kIsolated;
}
