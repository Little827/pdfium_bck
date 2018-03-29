// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "public/pdfium/pdfium.h"

#include <string>
#include <vector>

#include "core/fpdfapi/cpdf_modulemgr.h"
#include "core/fxcrt/unowned_ptr.h"
#include "core/fxge/cfx_gemodule.h"
#include "fpdfsdk/cpdfsdk_helpers.h"
#include "fxjs/ijs_runtime.h"
#include "third_party/base/ptr_util.h"

#ifdef PDF_ENABLE_XFA
#include "fxbarcode/BC_Library.h"
#endif  // PDF_ENABLE_XFA

namespace pdfium {
namespace {

bool g_library_initialized = false;

class UnsupportedFeatureAdapter : public UnsupportedFeatureIface {
 public:
  explicit UnsupportedFeatureAdapter(const UnsupportedFeatureDelegate* delegate)
      : delegate_(delegate) {}

  ~UnsupportedFeatureAdapter() override = default;

  void Handle(int error) const override {
    if (error < 0 ||
        error > static_cast<int>(UnsupportedFeatureDelegate::Feature::kLast)) {
      return;
    }

    // Status codes have a gap in them ...
    if (error == 9 || error == 10)
      return;

    delegate_->Handle(static_cast<UnsupportedFeatureDelegate::Feature>(error));
  }

 private:
  UnownedPtr<const UnsupportedFeatureDelegate> delegate_;
};

}  // namespace

Config::Config() = default;

Config::~Config() = default;

PDFIUM_EXPORT void PDFIUM_CALLCONV Initialize(const Config& config) {
  if (g_library_initialized)
    return;

  FXMEM_InitializePartitionAlloc();

  CFX_GEModule* pModule = CFX_GEModule::Get();
  std::vector<ByteString> byte_paths;
  for (const auto& path : config.user_font_paths)
    byte_paths.push_back(ByteString(path.c_str(), path.size()));

  pModule->Init(byte_paths);

  CPDF_ModuleMgr* pModuleMgr = CPDF_ModuleMgr::Get();
  pModuleMgr->Init();

#ifdef PDF_ENABLE_XFA
  BC_Library_Init();
#endif  // PDF_ENABLE_XFA

  IJS_Runtime::Initialize(config.js_embedder_slot, config.js_isolate);

  g_library_initialized = true;
}

PDFIUM_EXPORT void PDFIUM_CALLCONV Shutdown() {
  if (!g_library_initialized)
    return;

#ifdef PDF_ENABLE_XFA
  BC_Library_Destroy();
#endif  // PDF_ENABLE_XFA

  CPDF_ModuleMgr::Destroy();
  CFX_GEModule::Destroy();
  IJS_Runtime::Destroy();

  g_library_initialized = false;
}

PDFIUM_EXPORT void PDFIUM_CALLCONV
SetUnsupportedFeatureDelegate(const UnsupportedFeatureDelegate* delegate) {
  CPDF_ModuleMgr::Get()->SetUnsupportFeatureHandler(
      pdfium::MakeUnique<UnsupportedFeatureAdapter>(delegate));
}

PDFIUM_EXPORT Status PDFIUM_CALLCONV GetLastStatus() {
  return static_cast<Status>(GetLastError());
}

PDFIUM_EXPORT std::string PDFIUM_CALLCONV StatusString(Status status) {
  switch (status) {
    case Status::kSuccess:
      return "success";
    case Status::kUnknownError:
      return "unknown";
    case Status::kFileNotFoundOrFileError:
      return "file not found or file error";
    case Status::kFileInvalid:
      return "invalid pdf file";
    case Status::kPasswordError:
      return "password required or incorrect";
    case Status::kUnsupportSecurityScheme:
      return "unsupported security scheme";
    case Status::kPageNotFoundOrContentError:
      return "page not found or content error";
#if PDF_EENABLE_XFA
    case Status::kXFALoadError:
      return "XFA load error";
    case Status::kXFALayoutErro:
      return "XFA layout error";
#endif  // PDF_ENABLE_XFA
  }
}

}  // namespace pdfium
