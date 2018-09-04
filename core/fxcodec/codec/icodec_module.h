// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef CORE_FXCODEC_CODEC_ICODEC_MODULE_H_
#define CORE_FXCODEC_CODEC_ICODEC_MODULE_H_

#include "core/fxcrt/fx_system.h"
#include "third_party/base/span.h"

class CFX_DIBAttribute;

class ICodec_Module {
 public:
  class Context {
   public:
    virtual ~Context() {}
  };

  virtual ~ICodec_Module() {}

  virtual FX_FILESIZE GetAvailInput(Context* pContext) const = 0;
  virtual bool Input(Context* pContext,
                     pdfium::span<uint8_t> src_buf,
                     CFX_DIBAttribute* pAttribute) = 0;
};

#endif  // CORE_FXCODEC_CODEC_ICODEC_MODULE_H_
