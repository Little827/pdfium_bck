// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fpdfsdk/fpdf_string.h"

// NOTE: |bsUTF16LE| must outlive the use of the result. Care must be taken
// since modifying the result would impact |bsUTF16LE|.
FPDF_WIDESTRING AsFPDFWideString(ByteString bsUTF16LE) {
  return reinterpret_cast<FPDF_WIDESTRING>(
      bsUTF16LE.GetBuffer(bsUTF16LE.GetLength()));
}
