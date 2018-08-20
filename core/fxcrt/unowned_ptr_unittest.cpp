// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcrt/unowned_ptr.h"

#include <utility>
#include <vector>

#include "testing/gtest/include/gtest/gtest.h"

namespace fxcrt {
namespace {

class Clink {
 public:
  UnownedPtr<Clink> next_ = nullptr;
};

class SpecialClink : public Clink {
 public:
};

void DeleteDangling() {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  delete ptr1;
  delete ptr2;
}

void AssignDangling() {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  delete ptr1;
  ptr2->next_ = nullptr;
  delete ptr2;
}

void ReleaseDangling() {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  delete ptr1;
  ptr2->next_.Release();
  delete ptr2;
}

}  // namespace

TEST(UnownedPtr, PtrOk) {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  delete ptr2;
  delete ptr1;
}

TEST(UnownedPtr, PtrNotOk) {
#if defined(ADDRESS_SANITIZER)
  EXPECT_DEATH(DeleteDangling(), "");
#else
  DeleteDangling();
#endif
}

TEST(UnownedPtr, AssignOk) {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  ptr2->next_ = nullptr;
  delete ptr2;
  delete ptr1;
}

TEST(UnownedPtr, AssignNotOk) {
#if defined(ADDRESS_SANITIZER)
  EXPECT_DEATH(AssignDangling(), "");
#else
  AssignDangling();
#endif
}

TEST(UnownedPtr, ReleaseOk) {
  Clink* ptr1 = new Clink();
  Clink* ptr2 = new Clink();
  ptr2->next_ = ptr1;
  ptr2->next_.Release();
  delete ptr1;
  delete ptr2;
}

TEST(UnownedPtr, ReleaseNotOk) {
#if defined(ADDRESS_SANITIZER)
  EXPECT_DEATH(ReleaseDangling(), "");
#else
  ReleaseDangling();
#endif
}

TEST(UnownedPtr, OperatorEQ) {
  int foo;
  UnownedPtr<int> ptr1;
  EXPECT_TRUE(ptr1 == ptr1);

  UnownedPtr<int> ptr2;
  EXPECT_TRUE(ptr1 == ptr2);

  UnownedPtr<int> ptr3(&foo);
  EXPECT_TRUE(&foo == ptr3);
  EXPECT_TRUE(ptr3 == &foo);
  EXPECT_FALSE(ptr1 == ptr3);

  ptr1 = &foo;
  EXPECT_TRUE(ptr1 == ptr3);
}

TEST(UnownedPtr, OperatorNE) {
  int foo;
  UnownedPtr<int> ptr1;
  EXPECT_FALSE(ptr1 != ptr1);

  UnownedPtr<int> ptr2;
  EXPECT_FALSE(ptr1 != ptr2);

  UnownedPtr<int> ptr3(&foo);
  EXPECT_FALSE(&foo != ptr3);
  EXPECT_FALSE(ptr3 != &foo);
  EXPECT_TRUE(ptr1 != ptr3);

  ptr1 = &foo;
  EXPECT_FALSE(ptr1 != ptr3);
}

TEST(UnownedPtr, OperatorLT) {
  int foos[2];
  UnownedPtr<int> ptr1(&foos[0]);
  UnownedPtr<int> ptr2(&foos[1]);

  EXPECT_FALSE(ptr1 < ptr1);
  EXPECT_TRUE(ptr1 < ptr2);
  EXPECT_FALSE(ptr2 < ptr1);
}

TEST(UnownedPtr, ReleaseAssignSuperclassOK) {
  SpecialClink foo;
  UnownedPtr<SpecialClink> special_ptr(&foo);
  UnownedPtr<Clink> super_ptr(&foo);
  UnownedPtr<Clink> super_ptr2(special_ptr);
  UnownedPtr<Clink> super_ptr3;
  EXPECT_TRUE(super_ptr2 == special_ptr);

  super_ptr3 = special_ptr;
  EXPECT_FALSE(super_ptr3 != special_ptr);
  EXPECT_FALSE(super_ptr3 < special_ptr);
}

TEST(UnownedPtr, DowncastOK) {
  SpecialClink foo;
  UnownedPtr<Clink> super_ptr(&foo);
  UnownedPtr<SpecialClink> special_ptr(
      static_cast<UnownedPtr<SpecialClink>>(super_ptr));
  EXPECT_TRUE(super_ptr == special_ptr);

  special_ptr = static_cast<UnownedPtr<SpecialClink>>(super_ptr));
  EXPECT_FALSE(super_ptr != special_ptr);
  EXPECT_FALSE(super_ptr < special_ptr);
}

}  // namespace fxcrt
