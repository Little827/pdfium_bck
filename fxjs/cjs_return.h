// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#ifndef FXJS_CJS_RETURN_H_
#define FXJS_CJS_RETURN_H_

#include "fxjs/cfxjs_engine.h"
#include "fxjs/js_resources.h"
#include "third_party/base/optional.h"

class CJS_Return {
 public:
  // Wrap constructors with static methods so we can apply WARN_UNUSED_RESULT
  // otherwise we can't catch places where someone mistakenly writes
  //
  //     if (error)
  //       CJS_Return(JS_ERROR_CODE);
  //
  // instead of
  //
  //     if (error)
  //       return CJS_Return(JS_ERROR_CODE);
  //

  // Successful but empty return.
  static CJS_Return Success() WARN_UNUSED_RESULT { return CJS_Return(); }

  // Successful return with value.
  static CJS_Return Success(v8::Local<v8::Value> value) WARN_UNUSED_RESULT {
    return CJS_Return(value);
  }

  // Error with custom message.
  static CJS_Return Failure(const WideString& str) WARN_UNUSED_RESULT {
    return CJS_Return(str);
  }

  // Error with stock message.
  static CJS_Return Failure(JSMessage id) WARN_UNUSED_RESULT {
    return CJS_Return(id);
  }

  CJS_Return(const CJS_Return&);
  ~CJS_Return();

  bool HasError() const { return error_.has_value(); }
  WideString Error() const { return error_.value(); }

  bool HasReturn() const { return !return_.IsEmpty(); }
  v8::Local<v8::Value> Return() const { return return_; }

 private:
  CJS_Return();
  explicit CJS_Return(v8::Local<v8::Value>);
  explicit CJS_Return(const WideString&);
  explicit CJS_Return(JSMessage id);

  Optional<WideString> error_;
  v8::Local<v8::Value> return_;
};

#endif  // FXJS_CJS_RETURN_H_
