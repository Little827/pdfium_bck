// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_
#define CORE_FXGE_CFX_TEXTRENDEROPTIONS_H_

struct CFX_TextRenderOptions {
  // EdgingType defines the subpixel rendering options. The values are defined
  // in an incrementing order due to the latter subpixel type's dependency on
  // the previous one.
  enum EdgingType {
    kAliasing = 0,
    kAntiAliasing,

    // LCD optimization can only be enabled when anti-aliasing is enabled.
    kLcd,

    // BGR stripe optimization can only be enabled when LCD Mode is enabled.
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
