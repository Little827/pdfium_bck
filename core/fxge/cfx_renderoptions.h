// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_RENDEROPTIONS_H_
#define CORE_FXGE_CFX_RENDEROPTIONS_H_

class CFX_RenderOptions {
 public:
  // SubpixelType defines the subpixel rendering options. The values are defined
  // in an incrementing order due to the latter subpixel type's dependency on
  // the previous one.
  enum SubpixelType {
    kAntiAliasingDisabled = 0,
    kAntiAliasingEnabled,

    // LCD optimization can only be enabled when anti-aliasing is enabled.
    kLcd,

    // BGR stripe optimization can only be enabled when LCD Mode is enabled.
    kBgrStripe,
  };

  // Stores options for text rendering.
  struct TextOptions {
    TextOptions();
    ~TextOptions();

    // Not using the native text output available on some platforms.
    bool no_native_text = false;

    // Render texts as scalable graphics.
    bool print_graphic_text = false;

    // Render texts as images.
    bool print_image_text = false;

    // Subpixel rendering option.
    SubpixelType subpixel_type = kAntiAliasingEnabled;
  };

  // Stores font related options or flags.
  struct FontOptions {
    FontOptions();
    ~FontOptions();

    // Font is CID font.
    bool is_cid = false;
  };

  // TODO(crbug.com/pdfium/1531): Add more structs of different types of
  // options.

  CFX_RenderOptions();
  CFX_RenderOptions(const CFX_RenderOptions& other);
  ~CFX_RenderOptions();

  const FontOptions& GetFontOptions() const { return font_options_; }

  FontOptions& GetFontOptions() { return font_options_; }

  const TextOptions& GetTextOptions() const { return text_options_; }

  TextOptions& GetTextOptions() { return text_options_; }

  // Change the status for using LCD optimization. Enabling LCD will turn on
  // anti aliasing. Disabling LCD will turn off optimization for BGR stripe.
  void SetTextUseLcd(bool use_lcd);

 private:
  TextOptions text_options_;
  FontOptions font_options_;
};

#endif  // CORE_FXGE_CFX_RENDEROPTIONS_H_
