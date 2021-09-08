// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FXGE_WIN32_CFX_PSFONTTRACKER_H_
#define CORE_FXGE_WIN32_CFX_PSFONTTRACKER_H_

#include <stdint.h>

#include <set>

class CFX_Font;

class CFX_PSFontTracker {
 public:
  CFX_PSFontTracker();
  ~CFX_PSFontTracker();

  void AddFontObject(const CFX_Font* font);
  bool SeenFontObject(const CFX_Font* font) const;

 private:
  class ObjectIds {
   public:
    ObjectIds(uint32_t object_number, uint32_t generation_number);

    bool IsValid() const;
    bool operator<(const ObjectIds& other) const;

   private:
    const uint32_t object_number_;
    const uint32_t generation_number_;
  };

  // Tracks font objects via PDF object IDs, so if two CFX_Font instances are
  // for the same PDF object, then they are deduplicated.
  std::set<ObjectIds> seen_font_ids_;

  // For fonts without valid PDF object IDs, e.g. ones created in-memory, track
  // them by pointer.
  std::set<const CFX_Font*> seen_font_ptrs_;
};

#endif  // CORE_FXGE_WIN32_CFX_PSFONTTRACKER_H_
