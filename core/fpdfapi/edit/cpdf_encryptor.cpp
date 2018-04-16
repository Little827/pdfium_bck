// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/edit/cpdf_encryptor.h"
#include "core/fpdfapi/parser/cpdf_crypto_handler.h"

CPDF_Encryptor::CPDF_Encryptor(CPDF_CryptoHandler* pHandler,
                               int objnum,
                               pdfium::span<const uint8_t> src_data)
    : m_pData(src_data) {
  if (!pHandler)
    return;

  m_pNewBuf.resize(pHandler->EncryptGetSize(m_pData));
  m_pNewBuf.resize(pHandler->EncryptContent(objnum, 0, m_pData, m_pNewBuf));
  m_pData = m_pNewBuf;
}

CPDF_Encryptor::~CPDF_Encryptor() = default;
