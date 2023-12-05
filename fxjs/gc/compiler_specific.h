// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FXJS_GC_COMPILER_SPECIFIC_H_
#define FXJS_GC_COMPILER_SPECIFIC_H_

#include "build/build_config.h"

// TODO(crbug.com/1472363): Remove this file once the macro below is no longer
// in use.

#if defined(__clang__)
#define BLINK_GC_PLUGIN_IGNORE \
  __attribute__((annotate("blink_gc_plugin_ignore")))
#else
#define BLINK_GC_PLUGIN_IGNORE
#endif

#endif  // FXJS_GC_COMPILER_SPECIFIC_H_
