// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/cfx_fileaccess_posix.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>

#include "core/fxcrt/fx_stream.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif  // O_BINARY

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif  // O_LARGEFILE

namespace {

void GetFileMode(uint32_t dwModes, int32_t& nFlags, int32_t& nMasks) {
  nFlags = O_BINARY | O_LARGEFILE;
  if (dwModes & FX_FILEMODE_ReadOnly) {
    nFlags |= O_RDONLY;
    nMasks = 0;
  } else {
    nFlags |= O_RDWR | O_CREAT;
    if (dwModes & FX_FILEMODE_Truncate) {
      nFlags |= O_TRUNC;
    }
    nMasks = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  }
}

}  // namespace

// static
std::unique_ptr<FileAccessIface> FileAccessIface::Create() {
  return std::make_unique<CFX_FileAccess_Posix>();
}

CFX_FileAccess_Posix::CFX_FileAccess_Posix() : fd_(-1) {}

CFX_FileAccess_Posix::~CFX_FileAccess_Posix() {
  Close();
}

bool CFX_FileAccess_Posix::Open(ByteStringView fileName, uint32_t dwMode) {
  if (fd_ > -1)
    return false;

  int32_t nFlags;
  int32_t nMasks;
  GetFileMode(dwMode, nFlags, nMasks);

  // TODO(tsepez): check usage of c_str() below.
  fd_ = open(fileName.unterminated_c_str(), nFlags, nMasks);
  return fd_ > -1;
}

bool CFX_FileAccess_Posix::Open(WideStringView fileName, uint32_t dwMode) {
  return Open(FX_UTF8Encode(fileName).AsStringView(), dwMode);
}

void CFX_FileAccess_Posix::Close() {
  if (fd_ < 0) {
    return;
  }
  close(fd_);
  fd_ = -1;
}
FX_FILESIZE CFX_FileAccess_Posix::GetSize() const {
  if (fd_ < 0) {
    return 0;
  }
  struct stat s;
  memset(&s, 0, sizeof(s));
  fstat(fd_, &s);
  return s.st_size;
}
FX_FILESIZE CFX_FileAccess_Posix::GetPosition() const {
  if (fd_ < 0) {
    return (FX_FILESIZE)-1;
  }
  return lseek(fd_, 0, SEEK_CUR);
}
FX_FILESIZE CFX_FileAccess_Posix::SetPosition(FX_FILESIZE pos) {
  if (fd_ < 0) {
    return (FX_FILESIZE)-1;
  }
  return lseek(fd_, pos, SEEK_SET);
}
size_t CFX_FileAccess_Posix::Read(void* pBuffer, size_t szBuffer) {
  if (fd_ < 0) {
    return 0;
  }
  return read(fd_, pBuffer, szBuffer);
}
size_t CFX_FileAccess_Posix::Write(const void* pBuffer, size_t szBuffer) {
  if (fd_ < 0) {
    return 0;
  }
  return write(fd_, pBuffer, szBuffer);
}
size_t CFX_FileAccess_Posix::ReadPos(void* pBuffer,
                                     size_t szBuffer,
                                     FX_FILESIZE pos) {
  if (fd_ < 0) {
    return 0;
  }
  if (pos >= GetSize()) {
    return 0;
  }
  if (SetPosition(pos) == (FX_FILESIZE)-1) {
    return 0;
  }
  return Read(pBuffer, szBuffer);
}
size_t CFX_FileAccess_Posix::WritePos(const void* pBuffer,
                                      size_t szBuffer,
                                      FX_FILESIZE pos) {
  if (fd_ < 0) {
    return 0;
  }
  if (SetPosition(pos) == (FX_FILESIZE)-1) {
    return 0;
  }
  return Write(pBuffer, szBuffer);
}

bool CFX_FileAccess_Posix::Flush() {
  if (fd_ < 0)
    return false;

  return fsync(fd_) > -1;
}

bool CFX_FileAccess_Posix::Truncate(FX_FILESIZE szFile) {
  if (fd_ < 0)
    return false;

  return !ftruncate(fd_, szFile);
}
