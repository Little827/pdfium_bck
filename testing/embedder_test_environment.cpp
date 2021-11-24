// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/embedder_test_environment.h"

#include "core/fxcrt/fx_system.h"
#include "core/fxge/cfx_fontmapper.h"
#include "core/fxge/cfx_fontmgr.h"
#include "core/fxge/cfx_gemodule.h"
#include "core/fxge/systemfontinfo_iface.h"
#include "public/fpdfview.h"
#include "testing/utils/path_service.h"
#include "third_party/base/check.h"

#ifdef PDF_ENABLE_V8
#include "testing/v8_test_environment.h"
#endif  // PDF_ENABLE_V8

namespace {

EmbedderTestEnvironment* g_environment = nullptr;

struct {
  const char* face;
  const char* replacement;
} kFontFaceReplacements[] = {
    {"Arial", "Arimo"},     {"Calibri", "Tinos"},     {"Courier", "Cousine"},
    {"Helvetica", "Arimo"}, {"Times-Roman", "Tinos"}, {"Times", "Tinos"},
};

ByteString ReplaceFont(const ByteString& face) {
  if (face == "")
    return "Tinos";
  ByteString result = face;
  for (const auto& map : kFontFaceReplacements) {
    if (result.Replace(map.face, map.replacement))
      return result;
  }
  return result;
}

class Wrapper : public SystemFontInfoIface {
 public:
  Wrapper(std::unique_ptr<SystemFontInfoIface> impl) : impl_(std::move(impl)) {}
  ~Wrapper() = default;

  bool EnumFontList(CFX_FontMapper* pMapper) override {
    return impl_->EnumFontList(pMapper);
  }
  void* MapFont(int weight,
                bool bItalic,
                FX_Charset charset,
                int pitch_family,
                const ByteString& face) override {
    return impl_->MapFont(weight, bItalic, charset, pitch_family,
                          ReplaceFont(face));
  }
  void* GetFont(const ByteString& face) override {
    return impl_->GetFont(ReplaceFont(face));
  }
  uint32_t GetFontData(void* hFont,
                       uint32_t table,
                       pdfium::span<uint8_t> buffer) override {
    return impl_->GetFontData(hFont, table, buffer);
  }
  bool GetFaceName(void* hFont, ByteString* name) override {
    auto face = ReplaceFont(*name);
    return impl_->GetFaceName(hFont, &face);
  }
  bool GetFontCharset(void* hFont, FX_Charset* charset) override {
    return impl_->GetFontCharset(hFont, charset);
  }
  void DeleteFont(void* hFont) override { impl_->DeleteFont(hFont); }

 private:
  std::unique_ptr<SystemFontInfoIface> impl_;
};

}  // namespace

EmbedderTestEnvironment::EmbedderTestEnvironment() {
  DCHECK(!g_environment);
  g_environment = this;
}

EmbedderTestEnvironment::~EmbedderTestEnvironment() {
  DCHECK(g_environment);
  g_environment = nullptr;
}

// static
EmbedderTestEnvironment* EmbedderTestEnvironment::GetInstance() {
  return g_environment;
}

void EmbedderTestEnvironment::SetUp() {
  FPDF_LIBRARY_CONFIG config;
  config.version = 3;
  config.m_pUserFontPaths = nullptr;
  config.m_v8EmbedderSlot = 0;
  config.m_pPlatform = nullptr;

  ASSERT_TRUE(PathService::GetExecutableDir(&font_path_));
  font_path_.push_back(PATH_SEPARATOR);
  font_path_.append("test_fonts");
  font_paths_[0] = font_path_.c_str();
  font_paths_[1] = nullptr;
  config.m_pUserFontPaths = font_paths_;

#ifdef PDF_ENABLE_V8
  config.m_pIsolate = V8TestEnvironment::GetInstance()->isolate();
  config.m_pPlatform = V8TestEnvironment::GetInstance()->platform();
#else   // PDF_ENABLE_V8
  config.m_pIsolate = nullptr;
  config.m_pPlatform = nullptr;
#endif  // PDF_ENABLE_V8

  FPDF_InitLibraryWithConfig(&config);

  auto* font_mapper = CFX_GEModule::Get()->GetFontMgr()->GetBuiltinMapper();
  font_mapper->SetSystemFontInfo(
      std::make_unique<Wrapper>(font_mapper->TakeSystemFontInfo()));
}

void EmbedderTestEnvironment::TearDown() {
  FPDF_DestroyLibrary();
}
