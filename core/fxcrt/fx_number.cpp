// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_number.h"

#include <limits>

#include "core/fxcrt/fx_extension.h"
#include "core/fxcrt/fx_string.h"

FX_Number::FX_Number()
    : m_bInteger(true), m_bSigned(false), m_UnsignedValue(0) {}

FX_Number::FX_Number(uint32_t value)
    : m_bInteger(true), m_bSigned(false), m_UnsignedValue(value) {}

FX_Number::FX_Number(int32_t value)
    : m_bInteger(true), m_bSigned(true), m_SignedValue(value) {}

FX_Number::FX_Number(float value)
    : m_bInteger(false), m_bSigned(true), m_FloatValue(value) {}

FX_Number::FX_Number(const ByteStringView& strc) {
  if (strc.Contains('.')) {
    m_bInteger = false;
    m_bSigned = true;
    m_FloatValue = FX_atof(strc);
    return;
  }

  m_bInteger = true;
  m_bSigned = false;

  // Note, numbers in PDF are typically of the form 123, -123, etc. But,
  // for things like the Permissions on the encryption hash the number is
  // actually an unsigned value. We use a uint32_t so we can deal with the
  // unsigned and then check for overflow if the user actually signed the value.
  // The Permissions flag is listed in Table 3.20 PDF 1.7 spec.
  pdfium::base::CheckedNumeric<uint32_t> unsigned_val = 0;
  bool bNegative = false;
  size_t cc = 0;
  if (strc[0] == '+') {
    cc++;
    m_bSigned = true;
  } else if (strc[0] == '-') {
    bNegative = true;
    m_bSigned = true;
    cc++;
  }

  while (cc < strc.GetLength() && std::isdigit(strc[cc])) {
    unsigned_val = unsigned_val * 10 + FXSYS_DecimalCharToInt(strc.CharAt(cc));
    if (!unsigned_val.IsValid())
      break;
    cc++;
  }

  if (!m_bSigned) {
    m_UnsignedValue = unsigned_val.ValueOrDefault(0);
    return;
  }

  // We have a sign, and if the value was greater then a regular integer
  // we've overflowed, reset to the default value.
  if (bNegative) {
    if (unsigned_val.ValueOrDefault(0) >
        static_cast<uint32_t>(std::numeric_limits<int>::max()) + 1) {
      unsigned_val = 0;
    }
  } else if (unsigned_val.ValueOrDefault(0) >
             static_cast<uint32_t>(std::numeric_limits<int>::max())) {
    unsigned_val = 0;
  }

  // Switch back to the int space so we can flip to a negative if we need.
  uint32_t uValue = unsigned_val.ValueOrDefault(0);
  int32_t value = static_cast<int32_t>(uValue);
  if (bNegative) {
    // |value| is usually positive, except in the corner case of "-2147483648",
    // where |unsigned_val| is 2147483648. When it gets casted to an int,
    // |value| becomes -2147483648. For this case, avoid undefined behavior,
    // because an integer cannot represent 2147483648.
    static constexpr int kMinInt = std::numeric_limits<int>::min();
    m_SignedValue = LIKELY(value != kMinInt) ? -value : kMinInt;
  }
}

uint32_t FX_Number::GetUnsigned() const {
  return m_bInteger ? m_UnsignedValue : static_cast<uint32_t>(m_FloatValue);
}

int32_t FX_Number::GetSigned() const {
  return m_bInteger ? m_SignedValue : static_cast<int32_t>(m_FloatValue);
}

float FX_Number::GetFloat() const {
  if (!m_bInteger)
    return m_FloatValue;

  return m_bSigned ? static_cast<float>(m_SignedValue)
                   : static_cast<float>(m_UnsignedValue);
}
