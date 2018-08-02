// Copyright 2018 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fpdfapi/parser/cpdf_pages_tree.h"

#include <algorithm>

#include "core/fpdfapi/parser/cpdf_array.h"
#include "core/fpdfapi/parser/cpdf_dictionary.h"
#include "core/fpdfapi/parser/cpdf_document.h"
#include "core/fpdfapi/parser/cpdf_number.h"
#include "core/fpdfapi/parser/cpdf_read_validator.h"
#include "core/fpdfapi/parser/cpdf_reference.h"
#include "third_party/base/stl_util.h"

namespace {

const uint32_t kMaxPageLevel = 1024;
constexpr char kPages[] = "Pages";
constexpr char kKids[] = "Kids";
constexpr char kCount[] = "Count";
constexpr char kParent[] = "Parent";

}  // namespace

CPDF_PagesTree::CPDF_PagesTree(CPDF_IndirectObjectHolder* holder,
                               CPDF_Dictionary* root,
                               uint32_t pages_count,
                               const RetainPtr<CPDF_ReadValidator>& validator)
    : holder_(holder),
      root_(root),
      pages_count_(pages_count),
      validator_(validator) {
  ASSERT(root_);
}

CPDF_PagesTree::~CPDF_PagesTree() = default;

void CPDF_PagesTree::RetrievePageCount() {
  pages_count_ = 0;
  CPDF_Dictionary* pages_dict = root_->GetDictFor(kPages);
  if (!pages_dict)
    return;

  if (!pages_dict->KeyExist(kKids)) {
    pages_count_ = 1;
    return;
  }
  std::set<const CPDF_Dictionary*> visited_pages;
  visited_pages.insert(pages_dict);
  pages_count_ = CountPages(pages_dict, &visited_pages);
}

uint32_t CPDF_PagesTree::CountPages(
    CPDF_Dictionary* pages_dict,
    std::set<const CPDF_Dictionary*>* visited_pages) {
  CPDF_ReadValidator::Session read_session(validator_.Get());
  FX_SAFE_UINT32 safe_count = pages_dict->GetIntegerFor(kCount);
  if (CheckHasReadProblems())
    return 0;

  uint32_t count = safe_count.ValueOrDefault(0);
  if (count > 0 && count < CPDF_Document::kPageMaxNum)
    return count;

  CPDF_Array* pKidList = pages_dict->GetArrayFor(kKids);
  if (CheckHasReadProblems())
    return 0;

  if (!pKidList)
    return 0;
  count = 0;
  for (size_t i = 0; i < pKidList->GetCount(); i++) {
    CPDF_Dictionary* pKid = pKidList->GetDictAt(i);
    if (CheckHasReadProblems())
      return 0;

    if (!pKid || pdfium::ContainsKey(*visited_pages, pKid))
      continue;
    if (pKid->KeyExist(kKids)) {
      // Use |visited_pages| to help detect circular references of pages_dict.
      pdfium::ScopedSetInsertion<const CPDF_Dictionary*> local_add(
          visited_pages, pKid);
      count += CountPages(pKid, visited_pages);
      if (CheckHasReadProblems())
        return 0;

    } else {
      // This page is a leaf node.
      count++;
    }
  }
  ASSERT(!CheckHasReadProblems());
  pages_dict->SetNewFor<CPDF_Number>(kCount, static_cast<int>(count));
  return count;
}

CPDF_Dictionary* CPDF_PagesTree::TraversePDFPages(uint32_t page_index,
                                                  size_t level) {
  if (next_page_to_traverse_ > page_index || reached_max_page_level_)
    return nullptr;

  CPDF_ReadValidator::Session read_session(validator_.Get());

  CPDF_Dictionary* pages_dict = tree_traversal_[level].first;
  CPDF_Array* pKidList = pages_dict->GetArrayFor(kKids);
  if (CheckHasReadProblems())
    return nullptr;

  if (!pKidList) {
    tree_traversal_.pop_back();
    if (next_page_to_traverse_ != page_index)
      return nullptr;
    ++next_page_to_traverse_;
    SetPage(page_index, pages_dict);
    return pages_dict;
  }
  if (level >= kMaxPageLevel) {
    tree_traversal_.pop_back();
    reached_max_page_level_ = true;
    return nullptr;
  }
  CPDF_Dictionary* page = nullptr;
  for (size_t i = tree_traversal_[level].second; i < pKidList->GetCount();
       i++) {
    if (next_page_to_traverse_ > page_index)
      break;
    pKidList->ConvertToIndirectObjectAt(i, holder_.Get());
    CPDF_Dictionary* pKid = pKidList->GetDictAt(i);
    if (CheckHasReadProblems())
      return nullptr;

    if (!pKid) {
      ++next_page_to_traverse_;
      tree_traversal_[level].second++;
      continue;
    }
    if (pKid == pages_dict) {
      tree_traversal_[level].second++;
      continue;
    }
    if (!pKid->KeyExist(kKids)) {
      SetPage(next_page_to_traverse_, pKid);
      ++next_page_to_traverse_;
      tree_traversal_[level].second++;
      if (next_page_to_traverse_ > page_index) {
        page = pKid;
        break;
      }
    } else {
      // If the vector has size level+1, the child is not in yet
      if (tree_traversal_.size() == level + 1)
        tree_traversal_.push_back(std::make_pair(pKid, 0));
      // Now tree_traversal_[level+1] should exist and be equal to pKid.
      CPDF_Dictionary* pageKid = TraversePDFPages(page_index, level + 1);
      if (CheckHasReadProblems())
        return nullptr;

      // Check if child was completely processed, i.e. it popped itself out
      if (tree_traversal_.size() == level + 1)
        tree_traversal_[level].second++;
      // If child did not finish, no pages_dict to go, or max level reached, end
      if (tree_traversal_.size() != level + 1 ||
          next_page_to_traverse_ > page_index || reached_max_page_level_) {
        page = pageKid;
        break;
      }
    }
  }
  ASSERT(!CheckHasReadProblems());
  if (tree_traversal_[level].second == pKidList->GetCount())
    tree_traversal_.pop_back();

  return page;
}

bool CPDF_PagesTree::InsertNewPage(uint32_t page_index,
                                   CPDF_Dictionary* pPageDict) {
  CPDF_Dictionary* pages_dict = root_->GetDictFor(kPages);
  if (!pages_dict)
    return false;

  uint32_t nPages = static_cast<uint32_t>(pages_count());
  if (page_index < 0 || page_index > nPages)
    return false;

  if (page_index == nPages) {
    CPDF_ReadValidator::Session read_session(validator_.Get());
    CPDF_Array* pPagesList = pages_dict->GetArrayFor(kKids);
    if (CheckHasReadProblems())
      return false;

    if (!pPagesList)
      pPagesList = pages_dict->SetNewFor<CPDF_Array>(kKids);
    pPagesList->Add(pPageDict->MakeReference(holder_.Get()));
    pages_dict->SetNewFor<CPDF_Number>(kCount, static_cast<int>(nPages + 1));
    pPageDict->SetFor(kParent, pages_dict->MakeReference(holder_.Get()));
    ResetTraversal();
  } else {
    std::set<CPDF_Dictionary*> stack = {pages_dict};
    if (!InsertDeletePDFPage(pages_dict, page_index, pPageDict, true, &stack))
      return false;
  }
  ASSERT(!CheckHasReadProblems());
  ASSERT(pages_.size() >= static_cast<size_t>(page_index));
  ++pages_count_;
  pages_.emplace(pages_.begin() + page_index, pPageDict);
  return true;
}

bool CPDF_PagesTree::DeletePage(uint32_t page_index) {
  if (page_index >= pages_count())
    return false;

  CPDF_Dictionary* pages_dict = root_->GetDictFor(kPages);
  if (!pages_dict)
    return false;

  FX_SAFE_UINT32 nPages = pages_dict->GetIntegerFor(kCount);
  if (page_index >= nPages.ValueOrDefault(0))
    return false;

  std::set<CPDF_Dictionary*> stack = {pages_dict};
  if (!InsertDeletePDFPage(pages_dict, page_index, nullptr, false, &stack))
    return false;

  --pages_count_;
  if (pages_.size() > page_index)
    pages_.erase(pages_.begin() + page_index);

  return true;
}

CPDF_Dictionary* CPDF_PagesTree::PageAt(uint32_t page_index) {
  if (page_index >= pages_count())
    return nullptr;

  if (page_index < pages_.size() && pages_[page_index])
    return pages_[page_index].Get();

  if (page_index < next_page_to_traverse_)
    return nullptr;

  if (tree_traversal_.empty()) {
    ResetTraversal();
    CPDF_Dictionary* pages_dict = root_->GetDictFor(kPages);
    if (!pages_dict)
      return nullptr;

    tree_traversal_.push_back(std::make_pair(pages_dict, 0));
  }

  return TraversePDFPages(page_index, 0);
}

Optional<uint32_t> CPDF_PagesTree::GetPageIndex(uint32_t objnum) {
  uint32_t nPages = pages_.size();
  uint32_t skip_count = 0;
  bool bSkipped = false;
  for (uint32_t i = 0; i < nPages; i++) {
    if (pages_[i] && pages_[i]->GetObjNum() == objnum)
      return i;

    if (!bSkipped && !pages_[i]) {
      skip_count = i;
      bSkipped = true;
    }
  }

  const CPDF_Dictionary* pages_dict = root_->GetDictFor(kPages);
  if (!pages_dict)
    return {};

  uint32_t start_index = 0;
  const Optional<uint32_t> found_index =
      FindPageIndex(pages_dict, &skip_count, objnum, &start_index);

  if (found_index && *found_index < pages_count())
    return found_index;

  return {};
}

Optional<uint32_t> CPDF_PagesTree::FindPageIndex(const CPDF_Dictionary* node,
                                                 uint32_t* skip_count,
                                                 uint32_t objnum,
                                                 uint32_t* index,
                                                 uint32_t level) const {
  if (!node->KeyExist(kKids)) {
    if (objnum == node->GetObjNum())
      return *index;

    if (*skip_count)
      (*skip_count)--;

    (*index)++;
    return {};
  }

  const CPDF_Array* pKidList = node->GetArrayFor(kKids);
  if (!pKidList)
    return {};

  if (level >= kMaxPageLevel)
    return {};

  CPDF_ReadValidator::Session read_session(validator_.Get());
  size_t count = node->GetIntegerFor(kCount);
  if (CheckHasReadProblems())
    return {};

  if (count <= *skip_count) {
    (*skip_count) -= count;
    (*index) += count;
    return {};
  }

  if (count && count == pKidList->GetCount()) {
    for (size_t i = 0; i < count; i++) {
      const CPDF_Reference* pKid = ToReference(pKidList->GetObjectAt(i));
      if (pKid && pKid->GetRefObjNum() == objnum)
        return static_cast<uint32_t>(*index + i);
    }
  }

  for (size_t i = 0; i < pKidList->GetCount(); i++) {
    const CPDF_Dictionary* pKid = pKidList->GetDictAt(i);
    if (CheckHasReadProblems())
      return {};

    if (!pKid || pKid == node)
      continue;

    Optional<uint32_t> found_index =
        FindPageIndex(pKid, skip_count, objnum, index, level + 1);
    if (CheckHasReadProblems())
      return {};

    if (found_index)
      return found_index;
  }
  return {};
}

void CPDF_PagesTree::SetPage(uint32_t page_index, CPDF_Dictionary* page_dict) {
  ASSERT(page_index >= 0);
  pages_.resize(std::max(static_cast<size_t>(page_index + 1), pages_.size()));
  ASSERT(!pages_[page_index] || pages_[page_index] == page_dict);
  pages_[page_index] = page_dict;
}

bool CPDF_PagesTree::InsertDeletePDFPage(CPDF_Dictionary* pages_dict,
                                         uint32_t nPagesToGo,
                                         CPDF_Dictionary* pPageDict,
                                         bool bInsert,
                                         std::set<CPDF_Dictionary*>* pVisited) {
  CPDF_Array* pKidList = pages_dict->GetArrayFor(kKids);
  if (!pKidList)
    return false;

  CPDF_ReadValidator::Session read_session(validator_.Get());

  for (size_t i = 0; i < pKidList->GetCount(); i++) {
    CPDF_Dictionary* pKid = pKidList->GetDictAt(i);
    if (CheckHasReadProblems())
      return false;

    if (pKid->GetStringFor("Type") == "Page") {
      if (nPagesToGo != 0) {
        nPagesToGo--;
        continue;
      }
      if (bInsert) {
        pKidList->InsertAt(i, pPageDict->MakeReference(holder_.Get()));
        pPageDict->SetFor(kParent, pages_dict->MakeReference(holder_.Get()));
      } else {
        pKidList->RemoveAt(i);
      }
      pages_dict->SetNewFor<CPDF_Number>(
          kCount, pages_dict->GetIntegerFor(kCount) + (bInsert ? 1 : -1));
      ResetTraversal();
      break;
    }
    if (CheckHasReadProblems())
      return false;

    uint32_t nPages = pKid->GetIntegerFor(kCount);
    if (CheckHasReadProblems())
      return false;

    if (nPagesToGo >= nPages) {
      nPagesToGo -= nPages;
      continue;
    }
    if (pdfium::ContainsKey(*pVisited, pKid))
      return false;

    pdfium::ScopedSetInsertion<CPDF_Dictionary*> insertion(pVisited, pKid);
    if (!InsertDeletePDFPage(pKid, nPagesToGo, pPageDict, bInsert, pVisited))
      return false;

    pages_dict->SetNewFor<CPDF_Number>(
        kCount, pages_dict->GetIntegerFor(kCount) + (bInsert ? 1 : -1));
    break;
  }
  ASSERT(!CheckHasReadProblems());
  return true;
}

void CPDF_PagesTree::ResetTraversal() {
  next_page_to_traverse_ = 0;
  reached_max_page_level_ = false;
  tree_traversal_.clear();
}

bool CPDF_PagesTree::CheckHasReadProblems() const {
  return !!validator_ && validator_->has_read_problems();
}
