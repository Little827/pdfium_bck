// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_
#define CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_

struct CFX_TextRenderOptions {
  // EdgingType defines the options for drawing text edge pixels. The values
  // are defined in an incrementing order due to the latter edging type's
  // dependency on the previous one.
  enum EdgingType {
    // No transparent pixels on glyph edges.
    kAliasing = 0,

    // May have transparent pixels on glyph edges.
    kAntiAliasing,

    // LCD optimization, can be enabled when anti-aliasing is allowed.
    kLcd,

    // BGR stripe optimization, can be enabled when LCD optimazation is enabled.
    kBgrStripe,
  };

  CFX_TextRenderOptions();
  CFX_TextRenderOptions(EdgingType type);
  CFX_TextRenderOptions(const CFX_TextRenderOptions& other);
  ~CFX_TextRenderOptions();

  // Font is CID font. False by default.
  bool font_is_cid;

  // Using the native text output available on some platforms. True by default.
  bool native_text;

  // Subpixel rendering option. kAntiAliasing by default.
  EdgingType edging_type;
};

#endif  // CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_
