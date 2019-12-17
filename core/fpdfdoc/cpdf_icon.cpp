// Copyright 2019 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfdoc/cpdf_icon.h"

#include <algorithm>
#include <sstream>
#include <utility>

#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_stream.h"

CPDF_Icon::CPDF_Icon(CPDF_Stream* pStream) : m_pStream(pStream) {}

CPDF_Icon::~CPDF_Icon() = default;

CFX_SizeF CPDF_Icon::GetImageSize() {
  CPDF_Dictionary* pDict = m_pStream->GetDict();
  if (!pDict)
    return {0.0f, 0.0f};

  CFX_FloatRect rect = pDict->GetRectFor("BBox");
  return {rect.right - rect.left, rect.top - rect.bottom};
}

CFX_Matrix CPDF_Icon::GetImageMatrix() {
  if (CPDF_Dictionary* pDict = m_pStream->GetDict())
    return pDict->GetMatrixFor("Matrix");
  return CFX_Matrix();
}

ByteString CPDF_Icon::GetImageAlias() {
  if (CPDF_Dictionary* pDict = m_pStream->GetDict())
    return pDict->GetStringFor("Name");
  return ByteString();
}
