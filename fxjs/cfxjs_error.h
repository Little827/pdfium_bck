// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FXJS_CFXJS_ERROR_H_
#define FXJS_CFXJS_ERROR_H_

#include "core/fxcrt/widestring.h"

struct CFXJS_Error {
  int line;
  int column;
  WideString exception;

  CFXJS_Error(int line, int column, const WideString& exception);
};

#endif  // FXJS_CFXJS_ERROR_H_
