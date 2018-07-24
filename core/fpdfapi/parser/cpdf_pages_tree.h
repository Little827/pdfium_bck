// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_FPDFAPI_PARSER_CPDF_PAGES_TREE_H_
#define CORE_FPDFAPI_PARSER_CPDF_PAGES_TREE_H_

#include <set>
#include <utility>
#include <vector>

#include "core/fxcrt/unowned_ptr.h"
#include "third_party/base/optional.h"

class CPDF_Dictionary;
class CPDF_IndirectObjectHolder;

class CPDF_PagesTree {
 public:
  CPDF_PagesTree(CPDF_IndirectObjectHolder* holder,
                 CPDF_Dictionary* root,
                 uint32_t pages_count);
  ~CPDF_PagesTree();

  uint32_t pages_count() const { return pages_count_; }

  // Retrieve page count information by getting count value from the tree nodes
  void RetrievePageCount();

  bool InsertNewPage(uint32_t iPage, CPDF_Dictionary* pPageDict);
  bool DeletePage(uint32_t iPage);

  CPDF_Dictionary* PageAt(uint32_t page_index);

  Optional<uint32_t> GetPageIndex(uint32_t objnum);

 protected:
  Optional<uint32_t> FindPageIndex(const CPDF_Dictionary* pNode,
                                   uint32_t* skip_count,
                                   uint32_t objnum,
                                   uint32_t* index,
                                   uint32_t level = 0) const;
  uint32_t CountPages(CPDF_Dictionary* pPages,
                      std::set<const CPDF_Dictionary*>* visited_pages);
  // When this method is called, m_pTreeTraversal[level] exists.
  CPDF_Dictionary* TraversePDFPages(uint32_t iPage,
                                    uint32_t* nPagesToGo,
                                    size_t level);
  void SetPage(uint32_t page_index, CPDF_Dictionary* page_dict);
  bool InsertDeletePDFPage(CPDF_Dictionary* pPages,
                           uint32_t nPagesToGo,
                           CPDF_Dictionary* pPageDict,
                           bool bInsert,
                           std::set<CPDF_Dictionary*>* pVisited);
  void ResetTraversal();

  UnownedPtr<CPDF_IndirectObjectHolder> holder_;
  UnownedPtr<CPDF_Dictionary> root_;
  uint32_t pages_count_;
  bool reached_max_page_level_ = false;
  uint32_t next_page_to_traverse_ = 0;

  // Vector of pairs to know current position in the page tree. The index in the
  // vector corresponds to the level being described. The pair contains a
  // pointer to the dictionary being processed at the level, and an index of the
  // of the child being processed within the dictionary's /Kids array.
  std::vector<std::pair<CPDF_Dictionary*, size_t>> tree_traversal_;
  std::vector<UnownedPtr<CPDF_Dictionary>> pages_;
};

#endif  // CORE_FPDFAPI_PARSER_CPDF_PAGES_TREE_H_
