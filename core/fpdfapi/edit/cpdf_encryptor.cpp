// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fpdfapi/edit/cpdf_encryptor.h"
#include "core/fpdfapi/parser/cpdf_crypto_handler.h"

CPDF_Encryptor::CPDF_Encryptor(CPDF_CryptoHandler* pHandler,
                               int objnum,
                               const uint8_t* src_data,
                               uint32_t src_size) {
  if (src_size == 0)
    return;

  if (!pHandler) {
    m_Span = pdfium::make_span(src_data, src_size);
    return;
  }

  uint32_t buf_size = pHandler->EncryptGetSize(objnum, 0, src_data, src_size);
  m_NewBuf.resize(buf_size);
  pHandler->EncryptContent(objnum, 0, src_data, src_size, m_NewBuf.data(),
                           buf_size);  // Updates |buf_size| with actual.
  m_NewBuf.resize(buf_size);
  m_Span = m_NewBuf;
}

CPDF_Encryptor::~CPDF_Encryptor() {}
