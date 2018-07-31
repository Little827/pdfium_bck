// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_FX_FILE_RANGE_H_
#define CORE_FXCRT_FX_FILE_RANGE_H_

#include <utility>

#include "core/fxcrt/fx_safe_types.h"

class FX_FileRange {
 public:
  static const FX_FileRange kInvalid;

  FX_FileRange();
  template <typename Start, typename Size>
  FX_FileRange(Start start, Size size) : start_(start), size_(size) {}

  template <typename Start, typename Size>
  explicit FX_FileRange(const std::pair<Start, Size>& range)
      : FX_FileRange(range.first, range.second) {}

  FX_FileRange(const FX_FileRange& other);
  FX_FileRange(FX_FileRange&& other);
  FX_FileRange& operator=(const FX_FileRange& other);

  bool IsValid() const;
  std::pair<FX_FILESIZE, size_t> RangeOrDie() const;
  FX_FILESIZE StartOrDie() const;
  FX_FILESIZE EndOrDie() const;
  size_t SizeOrDie() const;
  bool IsEmpty() const { return IsValid() && (StartOrDie() == EndOrDie()); }

  template <typename Start>
  void SetStart(Start start) {
    start_ = start;
  }

  template <typename Size>
  void SetSize(Size size) {
    size_ = size;
  }

  template <typename Offset>
  void Offset(Offset offset) {
    start_ += offset;
  }

  template <typename Size>
  void Enlarge(Size size) {
    size_ += size;
  }

  bool Contains(const FX_FileRange& other) const;

  void Intersect(const FX_FileRange& other);

 private:
  FX_SAFE_FILESIZE start_;
  FX_SAFE_SIZE_T size_;
};

#endif  // CORE_FXCRT_FX_FILE_RANGE_H_
