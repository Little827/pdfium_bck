// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_number.h"

#include <limits>

#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_safe_types.h"
#include "core/fxcrt/fx_string.h"

FX_Number::FX_Number() : integer_(true), signed_(false), unsigned_value_(0) {}

FX_Number::FX_Number(int32_t value)
    : integer_(true), signed_(true), signed_value_(value) {}

FX_Number::FX_Number(float value)
    : integer_(false), signed_(true), float_value_(value) {}

FX_Number::FX_Number(ByteStringView strc)
    : integer_(true), signed_(false), unsigned_value_(0) {
  if (strc.IsEmpty())
    return;

  if (strc.Contains('.')) {
    integer_ = false;
    signed_ = true;
    float_value_ = StringToFloat(strc);
    return;
  }

  // Note, numbers in PDF are typically of the form 123, -123, etc. But,
  // for things like the Permissions on the encryption hash the number is
  // actually an unsigned value. We use a uint32_t so we can deal with the
  // unsigned and then check for overflow if the user actually signed the value.
  // The Permissions flag is listed in Table 3.20 PDF 1.7 spec.
  FX_SAFE_UINT32 unsigned_val = 0;
  bool bNegative = false;
  size_t cc = 0;
  if (strc[0] == '+') {
    cc++;
    signed_ = true;
  } else if (strc[0] == '-') {
    bNegative = true;
    signed_ = true;
    cc++;
  }

  while (cc < strc.GetLength() && std::isdigit(strc[cc])) {
    unsigned_val = unsigned_val * 10 + FXSYS_DecimalCharToInt(strc.CharAt(cc));
    if (!unsigned_val.IsValid())
      break;
    cc++;
  }

  uint32_t uValue = unsigned_val.ValueOrDefault(0);
  if (!signed_) {
    unsigned_value_ = uValue;
    return;
  }

  // We have a sign, so if the value was greater then the signed integer
  // limits, then we've overflowed and must reset to the default value.
  constexpr uint32_t uLimit =
      static_cast<uint32_t>(std::numeric_limits<int>::max());

  if (uValue > (bNegative ? uLimit + 1 : uLimit))
    uValue = 0;

  // Switch back to the int space so we can flip to a negative if we need.
  int32_t value = static_cast<int32_t>(uValue);
  if (bNegative) {
    // |value| is usually positive, except in the corner case of "-2147483648",
    // where |uValue| is 2147483648. When it gets casted to an int, |value|
    // becomes -2147483648. For this case, avoid undefined behavior, because
    // an int32_t cannot represent 2147483648.
    static constexpr int kMinInt = std::numeric_limits<int>::min();
    signed_value_ = LIKELY(value != kMinInt) ? -value : kMinInt;
  } else {
    signed_value_ = value;
  }
}

int32_t FX_Number::GetSigned() const {
  return integer_ ? signed_value_ : static_cast<int32_t>(float_value_);
}

float FX_Number::GetFloat() const {
  if (!integer_)
    return float_value_;

  return signed_ ? static_cast<float>(signed_value_)
                 : static_cast<float>(unsigned_value_);
}
