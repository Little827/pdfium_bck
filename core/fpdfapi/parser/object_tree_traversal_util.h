// Copyright 2023 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_PARSER_OBJECT_TREE_TRAVERSAL_UTIL_H_
#define CORE_FPDFAPI_PARSER_OBJECT_TREE_TRAVERSAL_UTIL_H_

#include <stdint.h>

#include <set>

class CPDF_Document;

// Traverses `document` starting with its trailer, if it has one, or starting at
// the catalog, which always exists. The trailer should have a reference to the
// catalog. The traversal avoids cycles.
// Returns all the PDF objects (not CPDF_Objects) the traversal reached as a set
// of object numbers.
std::set<uint32_t> GetObjectsWithReferences(const CPDF_Document* document);

// Same as GetObjectsWithReferences(), but only returns the objects with
// multiple references. Cycles are ignored.
// e.g. A -> B
//      A -> C
//      B -> D
//      C -> D
//
//  returns {D}, since both B and C references to D.
//
// e.g. A -> B
//      B -> C
//      C -> B
//
// returns {}, even though both A and C references B.
std::set<uint32_t> GetObjectsWithMultipleReferences(
    const CPDF_Document* document);

#endif  // CORE_FPDFAPI_PARSER_OBJECT_TREE_TRAVERSAL_UTIL_H_
