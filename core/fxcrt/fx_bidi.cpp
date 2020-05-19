// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_bidi.h"

#include <algorithm>

#include "core/fxcrt/fx_unicode.h"
#include "third_party/base/stl_util.h"

CFX_BidiChar::CFX_BidiChar()
    : current_segment_({0, 0, NEUTRAL}), last_segment_({0, 0, NEUTRAL}) {}

bool CFX_BidiChar::AppendChar(wchar_t wch) {
  Direction direction;
  switch (FX_GetBidiClass(wch)) {
    case FX_BIDICLASS::kL:
    case FX_BIDICLASS::kAN:
    case FX_BIDICLASS::kEN:
      direction = LEFT;
      break;
    case FX_BIDICLASS::kR:
    case FX_BIDICLASS::kAL:
      direction = RIGHT;
      break;
    default:
      direction = NEUTRAL;
      break;
  }

  bool bChangeDirection = (direction != current_segment_.direction);
  if (bChangeDirection)
    StartNewSegment(direction);

  current_segment_.count++;
  return bChangeDirection;
}

bool CFX_BidiChar::EndChar() {
  StartNewSegment(NEUTRAL);
  return last_segment_.count > 0;
}

void CFX_BidiChar::StartNewSegment(CFX_BidiChar::Direction direction) {
  last_segment_ = current_segment_;
  current_segment_.start += current_segment_.count;
  current_segment_.count = 0;
  current_segment_.direction = direction;
}

CFX_BidiString::CFX_BidiString(const WideString& str) : str_(str) {
  CFX_BidiChar bidi;
  for (wchar_t c : str_) {
    if (bidi.AppendChar(c))
      order_.push_back(bidi.GetSegmentInfo());
  }
  if (bidi.EndChar())
    order_.push_back(bidi.GetSegmentInfo());

  size_t nR2L = std::count_if(order_.begin(), order_.end(),
                              [](const CFX_BidiChar::Segment& seg) {
                                return seg.direction == CFX_BidiChar::RIGHT;
                              });

  size_t nL2R = std::count_if(order_.begin(), order_.end(),
                              [](const CFX_BidiChar::Segment& seg) {
                                return seg.direction == CFX_BidiChar::LEFT;
                              });

  if (nR2L > 0 && nR2L >= nL2R)
    SetOverallDirectionRight();
}

CFX_BidiString::~CFX_BidiString() {}

CFX_BidiChar::Direction CFX_BidiString::OverallDirection() const {
  ASSERT(overall_direction_ != CFX_BidiChar::NEUTRAL);
  return overall_direction_;
}

void CFX_BidiString::SetOverallDirectionRight() {
  if (overall_direction_ != CFX_BidiChar::RIGHT) {
    std::reverse(order_.begin(), order_.end());
    overall_direction_ = CFX_BidiChar::RIGHT;
  }
}
