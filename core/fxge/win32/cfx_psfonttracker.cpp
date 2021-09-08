// Copyright 2021 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxge/win32/cfx_psfonttracker.h"

#include "core/fxge/cfx_font.h"
#include "third_party/base/check.h"
#include "third_party/base/containers/contains.h"

CFX_PSFontTracker::ObjectIds::ObjectIds(uint32_t object_number,
                                        uint32_t generation_number)
    : object_number_(object_number), generation_number_(generation_number) {}

bool CFX_PSFontTracker::ObjectIds::IsValid() const {
  return object_number_ != 0 || generation_number_ != 0;
}

bool CFX_PSFontTracker::ObjectIds::operator<(const ObjectIds& other) const {
  return object_number_ < other.object_number_ ||
         (object_number_ == other.object_number_ &&
          generation_number_ < other.generation_number_);
}

CFX_PSFontTracker::CFX_PSFontTracker() = default;

CFX_PSFontTracker::~CFX_PSFontTracker() = default;

void CFX_PSFontTracker::AddFontObject(const CFX_Font* font) {
  ObjectIds ids(font->GetObjectNumber(), font->GetGenerationNumber());
  bool inserted;
  if (ids.IsValid())
    inserted = seen_font_ids_.insert(ids).second;
  else
    inserted = seen_font_ptrs_.insert(font).second;
  DCHECK(inserted);
}

bool CFX_PSFontTracker::SeenFontObject(const CFX_Font* font) const {
  ObjectIds ids(font->GetObjectNumber(), font->GetGenerationNumber());
  if (ids.IsValid())
    return pdfium::Contains(seen_font_ids_, ids);
  return pdfium::Contains(seen_font_ptrs_, font);
}
