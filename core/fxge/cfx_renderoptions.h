// Copyright 2020 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_CFX_RENDEROPTIONS_H_
#define CORE_FXGE_CFX_RENDEROPTIONS_H_

class CFX_RenderOptions {
 public:
  // Stores options for text rendering.
  struct TextOptions {
    TextOptions();
    ~TextOptions();

    // Use anti aliasing for text rendering.
    bool anti_aliasing = true;

    // Rendering texts for BGR stripes.
    bool bgr_stripe = false;

    // Not using the native text output avaible on some platforms
    bool no_native_text = false;

    // Render texts as scalable graphics.
    bool print_graphic_text = false;

    // Render texts as images.
    bool print_image_text = false;

    // Rendering texts for LCD display.
    bool use_lcd = false;
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
  CFX_RenderOptions(const CFX_RenderOptions& rhs);
  ~CFX_RenderOptions();

  const FontOptions& GetFontOptions() const { return font_options_; }

  FontOptions& GetFontOptions() { return font_options_; }

  const TextOptions& GetTextOptions() const { return text_options_; }

  TextOptions& GetTextOptions() { return text_options_; }

  // Sets the flag for using LCD optimizaiton in |text_options_|.
  void SetTextUseLcd(bool use_lcd);

 private:
  TextOptions text_options_;
  FontOptions font_options_;
};

#endif  // CORE_FXGE_CFX_RENDEROPTIONS_H_
