// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "fxjs/cfxjs_error.h"

CFXJS_Error::CFXJS_Error(int line, int column, const WideString& exception)
    : line(line), column(column), exception(exception) {}
