// Copyright 2016 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/render/cpdf_type3glyphs.h"

#include <map>

#include "core/fxge/fx_font.h"

namespace {

int AdjustBlueHelper(float pos, int* count, int blues[]) {
  float min_distance = 1000000.0f;
  int closest_pos = -1;
  for (int i = 0; i < *count; ++i) {
    float distance = fabs(pos - static_cast<float>(blues[i]));
    if (distance < 1.0f * 80.0f / 100.0f && distance < min_distance) {
      min_distance = distance;
      closest_pos = i;
    }
  }
  if (closest_pos >= 0)
    return blues[closest_pos];
  int new_pos = FXSYS_round(pos);
  if (*count == TYPE3_MAX_BLUES)
    return new_pos;
  blues[(*count)++] = new_pos;
  return new_pos;
}

}  // namespace

CPDF_Type3Glyphs::CPDF_Type3Glyphs()
    : m_TopBlueCount(0), m_BottomBlueCount(0) {}

CPDF_Type3Glyphs::~CPDF_Type3Glyphs() {}

std::pair<int, int> CPDF_Type3Glyphs::AdjustBlue(float top, float bottom) {
  return std::make_pair(
      AdjustBlueHelper(top, &m_TopBlueCount, m_TopBlue),
      AdjustBlueHelper(bottom, &m_BottomBlueCount, m_BottomBlue));
}
