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

    bool bgr_stripe = false;

    // Not using the native text output on some platforms
    bool no_native_text = false;

    bool print_graphic_text = false;

    bool print_image_text = false;

    // Optimize text rendering for LCD display.
    bool use_lcd = false;
  };

  // Stores font related options or flags.
  struct FontOptions {
    FontOptions();

    ~FontOptions();

    // Font is CID font.
    bool is_cid = false;
  };

  CFX_RenderOptions();
  CFX_RenderOptions(const CFX_RenderOptions& rhs);
  ~CFX_RenderOptions();

  void SetTextUseLcd(bool use_lcd);

  const TextOptions& GetTextOptions() const { return text_options_; }

  TextOptions& GetTextOptions() { return text_options_; }

  const FontOptions& GetFontOptions() const { return font_options_; }

  FontOptions& GetFontOptions() { return font_options_; }

 private:
  TextOptions text_options_;
  FontOptions font_options_;

  // TODO(nigi): Add more types of options.
};

#endif  // CORE_FXGE_CFX_RENDEROPTIONS_H_
