// Copyright 2017 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "core/fxcrt/fx_stream.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "build/build_config.h"
#include "core/fxcrt/fileaccess_iface.h"
#include "core/fxcrt/fx_safe_types.h"

#if defined(OS_WIN)
#include <direct.h>

struct FX_FolderHandle {
  HANDLE handle_;
  bool end_;
  WIN32_FIND_DATAA find_data_;
};
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct FX_FolderHandle {
  ByteString path_;
  DIR* dir_;
};
#endif

namespace {

class CFX_CRTFileStream final : public IFX_SeekableStream {
 public:
  template <typename T, typename... Args>
  friend RetainPtr<T> pdfium::MakeRetain(Args&&... args);

  // IFX_SeekableStream:
  FX_FILESIZE GetSize() override { return file_->GetSize(); }
  bool IsEOF() override { return GetPosition() >= GetSize(); }
  FX_FILESIZE GetPosition() override { return file_->GetPosition(); }
  bool ReadBlockAtOffset(void* buffer,
                         FX_FILESIZE offset,
                         size_t size) override {
    return file_->ReadPos(buffer, size, offset) > 0;
  }
  size_t ReadBlock(void* buffer, size_t size) override {
    return file_->Read(buffer, size);
  }
  bool WriteBlockAtOffset(const void* buffer,
                          FX_FILESIZE offset,
                          size_t size) override {
    return !!file_->WritePos(buffer, size, offset);
  }
  bool Flush() override { return file_->Flush(); }

 private:
  explicit CFX_CRTFileStream(std::unique_ptr<FileAccessIface> pFA)
      : file_(std::move(pFA)) {}
  ~CFX_CRTFileStream() override {}

  std::unique_ptr<FileAccessIface> file_;
};

}  // namespace

// static
RetainPtr<IFX_SeekableStream> IFX_SeekableStream::CreateFromFilename(
    const char* filename,
    uint32_t dwModes) {
  std::unique_ptr<FileAccessIface> pFA = FileAccessIface::Create();
  if (!pFA->Open(filename, dwModes))
    return nullptr;
  return pdfium::MakeRetain<CFX_CRTFileStream>(std::move(pFA));
}

// static
RetainPtr<IFX_SeekableStream> IFX_SeekableStream::CreateFromFilename(
    const wchar_t* filename,
    uint32_t dwModes) {
  std::unique_ptr<FileAccessIface> pFA = FileAccessIface::Create();
  if (!pFA->Open(filename, dwModes))
    return nullptr;
  return pdfium::MakeRetain<CFX_CRTFileStream>(std::move(pFA));
}

// static
RetainPtr<IFX_SeekableReadStream> IFX_SeekableReadStream::CreateFromFilename(
    const char* filename) {
  return IFX_SeekableStream::CreateFromFilename(filename, FX_FILEMODE_ReadOnly);
}

bool IFX_SeekableWriteStream::WriteBlock(const void* pData, size_t size) {
  return WriteBlockAtOffset(pData, GetSize(), size);
}

bool IFX_SeekableReadStream::IsEOF() {
  return false;
}

FX_FILESIZE IFX_SeekableReadStream::GetPosition() {
  return 0;
}

size_t IFX_SeekableReadStream::ReadBlock(void* buffer, size_t size) {
  return 0;
}

bool IFX_SeekableStream::WriteBlock(const void* buffer, size_t size) {
  return WriteBlockAtOffset(buffer, GetSize(), size);
}

bool IFX_SeekableStream::WriteString(ByteStringView str) {
  return WriteBlock(str.unterminated_c_str(), str.GetLength());
}

FX_FolderHandle* FX_OpenFolder(const char* path) {
  auto handle = std::make_unique<FX_FolderHandle>();
#if defined(OS_WIN)
  handle->handle_ =
      FindFirstFileExA((ByteString(path) + "/*.*").c_str(), FindExInfoStandard,
                       &handle->find_data_, FindExSearchNameMatch, nullptr, 0);
  if (handle->handle_ == INVALID_HANDLE_VALUE)
    return nullptr;

  handle->end_ = false;
#else
  DIR* dir = opendir(path);
  if (!dir)
    return nullptr;

  handle->path_ = path;
  handle->dir_ = dir;
#endif
  return handle.release();
}

bool FX_GetNextFile(FX_FolderHandle* handle,
                    ByteString* filename,
                    bool* bFolder) {
  if (!handle)
    return false;

#if defined(OS_WIN)
  if (handle->end_)
    return false;

  *filename = handle->find_data_.cFileName;
  *bFolder =
      (handle->find_data_.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  if (!FindNextFileA(handle->handle_, &handle->find_data_))
    handle->end_ = true;
  return true;
#else
  struct dirent* de = readdir(handle->dir_);
  if (!de)
    return false;
  ByteString fullpath = handle->path_ + "/" + de->d_name;
  struct stat deStat;
  if (stat(fullpath.c_str(), &deStat) < 0)
    return false;

  *filename = de->d_name;
  *bFolder = S_ISDIR(deStat.st_mode);
  return true;
#endif
}

void FX_CloseFolder(FX_FolderHandle* handle) {
  if (!handle)
    return;

#if defined(OS_WIN)
  FindClose(handle->handle_);
#else
  closedir(handle->dir_);
#endif
  delete handle;
}
