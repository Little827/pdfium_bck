// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/fx_file_range.h"

#include <algorithm>

// static
const FX_FileRange FX_FileRange::kInvalid(-1, -1);

FX_FileRange::FX_FileRange() = default;

FX_FileRange::FX_FileRange(const FX_FileRange& other) = default;

FX_FileRange::FX_FileRange(FX_FileRange&& other) = default;

FX_FileRange& FX_FileRange::operator=(const FX_FileRange& other) = default;

bool FX_FileRange::IsValid() const {
  return start_.IsValid() && size_.IsValid() &&
         (start_ + size_.ValueOrDie()).IsValid();
}

std::pair<FX_FILESIZE, size_t> FX_FileRange::RangeOrDie() const {
  return std::make_pair(start_.ValueOrDie(), size_.ValueOrDie());
}

FX_FILESIZE FX_FileRange::StartOrDie() const {
  return start_.ValueOrDie();
}

FX_FILESIZE FX_FileRange::EndOrDie() const {
  FX_SAFE_FILESIZE result = start_;
  result += size_.ValueOrDie();
  return result.ValueOrDie();
}

size_t FX_FileRange::SizeOrDie() const {
  return size_.ValueOrDie();
}

bool FX_FileRange::Contains(const FX_FileRange& other) const {
  if (!IsValid() || !other.IsValid())
    return false;

  return StartOrDie() <= other.StartOrDie() && other.EndOrDie() <= EndOrDie();
}

void FX_FileRange::Intersect(const FX_FileRange& other) {
  if (!IsValid())
    return;

  if (!other.IsValid()) {
    operator=(kInvalid);
    return;
  }

  const FX_FILESIZE new_start = std::max(StartOrDie(), other.StartOrDie());
  const FX_FILESIZE new_end = std::min(EndOrDie(), other.EndOrDie());
  if (new_end < new_start) {
    operator=(kInvalid);
    return;
  }
  start_ = new_start;
  size_ = new_end - new_start;
}
