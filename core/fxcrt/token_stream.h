// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXCRT_TOKEN_STREAM_H_
#define CORE_FXCRT_TOKEN_STREAM_H_

#include <iostream>
#include <string>

#include "core/fxcrt/fx_coordinates.h"

#include "third_party/skia_shared/SkFloatToDecimal.h"

namespace fxcrt {

class TokenStream {
 public:
  explicit TokenStream(std::ostream* underlying_stream)
      : underlying_stream_(underlying_stream) {}

  void SetSeparator(const std::string& separator) { separator_ = separator; }
  std::ostream& NormalStream() { return *underlying_stream_; }

  template <typename T>
  TokenStream& operator<<(const T& what) {
    if (primed_)
      *underlying_stream_ << separator_;
    *underlying_stream_ << what;
    primed_ = true;
    return *this;
  }

  // Don't allow locale to affect float format.
  TokenStream& operator<<(float value) {
    if (primed_)
      *underlying_stream_ << separator_;
    char buffer[pdfium::skia::kMaximumSkFloatToDecimalLength];
    unsigned size = pdfium::skia::SkFloatToDecimal(value, buffer);
    underlying_stream_->write(buffer, size);
    primed_ = true;
    return *this;
  }

  TokenStream& operator<<(const CFX_PointF& pt) {
    return *this << pt.x << pt.y;
  }

  TokenStream& operator<<(const CFX_Matrix& mx) {
    return *this << mx.a << mx.b << mx.c << mx.d << mx.e << mx.f;
  }

 private:
  bool primed_ = false;
  std::string separator_ = " ";
  std::ostream* underlying_stream_;
};

}  // namespace fxcrt

using fxcrt::TokenStream;

#endif  // CORE_FXCRT_TOKEN_STREAM_H_
