// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxge/dib/weight_table.h"

#include <algorithm>
#include <utility>

#include "core/fxge/dib/fx_dib.h"

namespace {

inline uint32_t FixedFromFloat(float f) {
  return static_cast<uint32_t>(FXSYS_roundf(f * WeightTable::kFixedPointOne));
}

}  // namespace

namespace fxge {

WeightTable::WeightTable() = default;

WeightTable::~WeightTable() = default;

bool WeightTable::CalculateWeights(int dest_len,
                                   int dest_min,
                                   int dest_max,
                                   int src_len,
                                   int src_min,
                                   int src_max,
                                   const FXDIB_ResampleOptions& options) {
  // 512MB should be large enough for this while preventing OOM.
  static constexpr size_t kMaxTableBytesAllowed = 512 * 1024 * 1024;

  // Help the compiler realize that these can't change during a loop iteration:
  const bool bilinear = options.bInterpolateBilinear;

  m_DestMin = 0;
  m_ItemSizeBytes = 0;
  m_WeightTablesSizeBytes = 0;
  m_WeightTables.clear();
  if (dest_min > dest_max)
    return false;

  m_DestMin = dest_min;

  // TODO(tsepez): test results are sensitive to `scale` being a double
  // rather than a float with an initial value no more precise than float.
  const double scale = static_cast<float>(src_len) / dest_len;
  const double base = dest_len < 0 ? src_len : 0;
  const size_t weight_count = static_cast<size_t>(ceil(fabs(scale))) + 1;
  m_ItemSizeBytes = PixelWeight::TotalBytesForWeightCount(weight_count);

  const size_t dest_range = static_cast<size_t>(dest_max - dest_min);
  const size_t kMaxTableItemsAllowed = kMaxTableBytesAllowed / m_ItemSizeBytes;
  if (dest_range > kMaxTableItemsAllowed)
    return false;

  m_WeightTablesSizeBytes = dest_range * m_ItemSizeBytes;
  m_WeightTables.resize(m_WeightTablesSizeBytes);
  if (options.bNoSmoothing || fabs(static_cast<float>(scale)) < 1.0f) {
    for (int dest_pixel = dest_min; dest_pixel < dest_max; ++dest_pixel) {
      WeightVector& pixel_weights = *GetPixelWeights(dest_pixel);
      double src_pos = dest_pixel * scale + scale / 2 + base;
      if (bilinear) {
        int src_start =
            static_cast<int>(floor(static_cast<float>(src_pos) - 1.0f / 2));
        int src_end =
            static_cast<int>(floor(static_cast<float>(src_pos) + 1.0f / 2));
        src_start = std::max(src_start, src_min);
        src_end = std::min(src_end, src_max - 1);
        pixel_weights.SetStartEnd(src_start, src_end, weight_count);
        if (pixel_weights.m_SrcStart == pixel_weights.m_SrcEnd) {
          pixel_weights.m_Weights[0] = kFixedPointOne;
        } else {
          pixel_weights.m_Weights[1] = FixedFromFloat(
              static_cast<float>(src_pos - pixel_weights.m_SrcStart - 0.5f));
          pixel_weights.m_Weights[0] =
              kFixedPointOne - pixel_weights.m_Weights[1];
        }
      } else {
        int pixel_pos = static_cast<int>(floor(static_cast<float>(src_pos)));
        int src_start = std::max(pixel_pos, src_min);
        int src_end = std::min(pixel_pos, src_max - 1);
        pixel_weights.SetStartEnd(src_start, src_end, weight_count);
        pixel_weights.m_Weights[0] = kFixedPointOne;
      }
    }
    return true;
  }

  for (int dest_pixel = dest_min; dest_pixel < dest_max; ++dest_pixel) {
    WeightVector& pixel_weights = *GetPixelWeights(dest_pixel);
    double src_start = dest_pixel * scale + base;
    double src_end = src_start + scale;
    int start_i = floor(std::min(src_start, src_end));
    int end_i = floor(std::max(src_start, src_end));
    start_i = std::max(start_i, src_min);
    end_i = std::min(end_i, src_max - 1);
    pixel_weights.SetStartEnd(start_i, end_i, weight_count);
    for (int j = start_i; j <= end_i; ++j) {
      double dest_start = (j - base) / scale;
      double dest_end = (j + 1 - base) / scale;
      if (dest_start > dest_end)
        std::swap(dest_start, dest_end);
      double area_start = std::max(dest_start, static_cast<double>(dest_pixel));
      double area_end = std::min(dest_end, static_cast<double>(dest_pixel + 1));
      double weight = std::max(0.0, area_end - area_start);
      if (weight == 0 && j == end_i) {
        --pixel_weights.m_SrcEnd;
        break;
      }
      size_t idx = j - start_i;
      if (idx >= weight_count)
        return false;

      pixel_weights.m_Weights[idx] = FixedFromFloat(weight);
    }
  }
  return true;
}

const WeightTable::WeightVector* WeightTable::GetPixelWeights(int pixel) const {
  DCHECK(pixel >= m_DestMin);
  return reinterpret_cast<const WeightVector*>(
      &m_WeightTables[(pixel - m_DestMin) * m_ItemSizeBytes]);
}

}  // namespace fxge
