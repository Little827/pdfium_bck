// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBLIC_PDFIUM_UNSUPPORTED_FEATURE_DELEGATE_H_
#define PUBLIC_PDFIUM_UNSUPPORTED_FEATURE_DELEGATE_H_

namespace pdfium {

class UnsupportedFeatureDelegate {
 public:
  enum class Feature {
    kXFAForm = 1,
    kPortableCollection = 2,
    kAttachment = 3,
    kSecurity = 4,
    kSharedReview = 5,
    kSharedAcrobatForm = 6,
    kSharedFilesystemForm = 7,
    kSharedEmailForm = 8,
    k3DAnnotation = 11,
    kMovieAnnotation = 12,
    kSoundAnnotation = 13,
    kScreenMediaAnnotation = 14,
    kScreenRichMediaAnnotation = 15,
    kAttachmentAnnotation = 16,
    kSignatureAnnotation = 17,
    kLast = kSignatureAnnotation
  };

  virtual ~UnsupportedFeatureDelegate() = default;

  virtual void Handle(Feature feature) const = 0;

 protected:
  UnsupportedFeatureDelegate() = default;
};

}  // namespace pdfium

#endif  // PUBLIC_PDFIUM_UNSUPPORTED_FEATURE_DELEGATE_H_
