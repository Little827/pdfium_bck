// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_RENDER_CPDF_TRANSPARENCY_H_
#define CORE_FPDFAPI_RENDER_CPDF_TRANSPARENCY_H_

class CPDF_Transparency {
 public:
  CPDF_Transparency();

  bool IsGroup() const;
  bool IsIsolated() const;

  void SetGroup();
  void SetIsolated();

 private:
  int m_iTransparency = 0;
};

#endif  // CORE_FPDFAPI_RENDER_CPDF_TRANSPARENCY_H_
