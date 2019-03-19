// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCRT_CFX_SEEKABLESTREAMPROXY_H_
#define CORE_FXCRT_CFX_SEEKABLESTREAMPROXY_H_

#include "core/fxcrt/fx_stream.h"
#include "core/fxcrt/fx_system.h"
#include "core/fxcrt/retain_ptr.h"

class CFX_SeekableStreamProxy final : public Retainable {
 public:
  enum class From {
    Begin = 0,
    Current,
  };

  template <typename T, typename... Args>
  friend RetainPtr<T> pdfium::MakeRetain(Args&&... args);

  // Unlike IFX_SeekableStreamPrxoy, buffers and sizes are always in terms
  // of numbers of wchar_ts, not bytes.
  FX_FILESIZE GetSize();  // Estimate under worst possible expansion.
  FX_FILESIZE GetPosition();
  bool IsEOF();
  size_t ReadBlock(wchar_t* pStr, size_t size);

  uint16_t GetCodePage() const { return m_wCodePage; }
  void SetCodePage(uint16_t wCodePage);

 private:
  explicit CFX_SeekableStreamProxy(
      const RetainPtr<IFX_SeekableReadStream>& stream);
  ~CFX_SeekableStreamProxy() override;

  void Seek(From eSeek, FX_FILESIZE iOffset);
  size_t ReadData(uint8_t* pBuffer, size_t iBufferSize);

  uint16_t m_wCodePage;
  size_t m_wBOMLength;
  FX_FILESIZE m_iPosition;
  RetainPtr<IFX_SeekableReadStream> m_pStream;
};

#endif  // CORE_FXCRT_CFX_SEEKABLESTREAMPROXY_H_
