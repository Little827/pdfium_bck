// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FPDFSDK_FPDF_STRING_H_
#define FPDFSDK_FPDF_STRING_H_

#include "core/fxcrt/bytestring.h"
#include "public/fpdfview.h"

FPDF_WIDESTRING AsFPDFWideString(ByteString bsUTF16LE);

#endif  // FPDFSDK_FPDF_STRING_H_
