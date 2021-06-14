// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXGE_DIB_WEIGHT_TABLE_H_
#define CORE_FXGE_DIB_WEIGHT_TABLE_H_

#include <stdint.h>

#include <vector>

#include "core/fxcrt/fx_memory_wrappers.h"
#include "third_party/base/check_op.h"

struct FXDIB_ResampleOptions;

namespace fxge {

class WeightTable {
 public:
  static constexpr uint32_t kFixedPointBits = 16;
  static constexpr uint32_t kFixedPointOne = 1 << kFixedPointBits;

  struct WeightVector {
    static size_t TotalBytesForWeightCount(size_t weight_count);

    void SetStartEnd(int src_start, int src_end, size_t weight_count) {
      CHECK_LT(static_cast<size_t>(src_end - src_start), weight_count);
      m_SrcStart = src_start;
      m_SrcEnd = src_end;
    }

    uint32_t GetWeight(int pixel) const {
      CHECK_GE(pixel, m_SrcStart);
      CHECK_LE(pixel, m_SrcEnd);
      return m_Weights[pixel - m_SrcStart];
    }

    int m_SrcStart;
    int m_SrcEnd;           // Note: inclusive.
    uint32_t m_Weights[1];  // Not really 1, variable size.
  };

  WeightTable();
  ~WeightTable();

  bool CalculateWeights(int dest_len,
                        int dest_min,
                        int dest_max,
                        int src_len,
                        int src_min,
                        int src_max,
                        const FXDIB_ResampleOptions& options);

  const WeightVector* GetPixelWeights(int pixel) const;
  WeightVector* GetPixelWeights(int pixel) {
    return const_cast<WeightVector*>(
        static_cast<const WeightTable*>(this)->GetPixelWeights(pixel));
  }

 private:
  int m_DestMin = 0;
  size_t m_ItemSizeBytes = 0;
  size_t m_WeightTablesSizeBytes = 0;
  std::vector<uint8_t, FxAllocAllocator<uint8_t>> m_WeightTables;
};

}  // namespace fxge

using fxge::WeightTable;

#endif  // CORE_FXGE_DIB_WEIGHT_TABLE_H_
