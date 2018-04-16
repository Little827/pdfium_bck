// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FPDFAPI_EDIT_CPDF_ENCRYPTOR_H_
#define CORE_FPDFAPI_EDIT_CPDF_ENCRYPTOR_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "core/fxcrt/fx_memory.h"
#include "third_party/base/span.h"

class CPDF_CryptoHandler;

class CPDF_Encryptor {
 public:
  CPDF_Encryptor(CPDF_CryptoHandler* pHandler,
                 int objnum,
                 pdfium::span<const uint8_t> src_data);
  ~CPDF_Encryptor();

  uint32_t GetSize() const { return m_pData.size(); }
  const uint8_t* GetData() const { return m_pData.data(); }

 private:
  pdfium::span<const uint8_t> m_pData;
  std::vector<uint8_t> m_pNewBuf;
};

#endif  // CORE_FPDFAPI_EDIT_CPDF_ENCRYPTOR_H_
