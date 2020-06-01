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
  CFX_TextRenderOptions(const CFX_TextRenderOptions& other);
  ~CFX_TextRenderOptions();

  // Not using the native text output available on some platforms.
  bool no_native_text = false;

  // TODO(crbug.com/pdfium/1535): Clean up or add code coverage for text
  // rendering options |print_graphic_text| and |print_image_text|.

  // Render texts as scalable graphics.
  bool print_graphic_text = false;

  // Render texts as images.
  bool print_image_text = false;

  // Subpixel rendering option.
  EdgingType edging_type = kAntiAliasing;

  // Font is CID font.
  bool font_is_cid = false;

  // Change the status for using LCD optimization. Enabling LCD will turn on
  // anti aliasing. Disabling LCD will turn off optimization for BGR stripe.
  void SetTextUseLcd(bool use_lcd);
};

#endif  // CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_
