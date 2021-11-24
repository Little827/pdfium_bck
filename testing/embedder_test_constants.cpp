// Copyright 2020 The PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test_constants.h"

#include "build/build_config.h"

namespace pdfium {

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kAnnotationStampWithApChecksum[] =
    "fe59f903d7a167468d31c83fce1e55f7";
#else
#if defined(OS_APPLE)
const char kAnnotationStampWithApChecksum[] =
    "17d2d76ba4352fbab8934ac35217229c";
#else
const char kAnnotationStampWithApChecksum[] =
    "9e41f0b3f7e4f6d393f57b404a4de394";
#endif
#endif  // defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)

const char kBlankPage612By792Checksum[] = "1940568c9ba33bac5d0b1ee9558c76b3";

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kBug890322Checksum[] = "793689536cf64fe792c2f241888c0cf3";
#else
const char kBug890322Checksum[] = "6c674642154408e877d88c6c082d67e9";
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kHelloWorldChecksum[] = "fdfa3ba6a0da9cba3e438932a9a4d9c0";
#elif defined(OS_APPLE)
const char kHelloWorldChecksum[] = "2f64de98fcd521d6688d7e2d98cb2b01";
#else
const char kHelloWorldChecksum[] = "62b9261f546e2e31f4d56e9121189087";
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kHelloWorldRemovedChecksum[] = "6fba10d70b99ea687426cf5d2a3b0a58";
#elif defined(OS_APPLE)
const char kHelloWorldRemovedChecksum[] = "0f23757ffaed0619ab04b1fa2538e5bd";
#else
const char kHelloWorldRemovedChecksum[] = "8931c5a3547db48a0be22dd8f4d43c49";
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kManyRectanglesChecksum[] = "4e7e280c1597222afcb0ee3bb90ec119";
const char kRectanglesChecksum[] = "b4e411a6b5ffa59a50efede2efece597";
#else
const char kManyRectanglesChecksum[] = "b0170c575b65ecb93ebafada0ff0f038";
const char kRectanglesChecksum[] = "0a90de37f52127619c3dfb642b5fa2fe";
#endif

#if defined(_SKIA_SUPPORT_) || defined(_SKIA_SUPPORT_PATHS_)
const char kTextFormChecksum[] = "8c7d5e5e3a941d6549c94baf4e2369c8";
#elif defined(OS_APPLE)
const char kTextFormChecksum[] = "290a75a81e4efd53e736d68e6565326f";
#else
const char kTextFormChecksum[] = "1683a3f5c394cdab4f0b73e4eafe2e88";
#endif

}  // namespace pdfium
