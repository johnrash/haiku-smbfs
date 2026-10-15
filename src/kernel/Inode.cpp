/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Inode.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fs_cache.h>
#include <kernel.h>
#include <KernelExport.h>
#include <NodeMonitor.h>

#include "Volume.h"
#include "../smb2/Utf.h"

using namespace smb2;


static const size_t kDirectoryBufferSize = 65536;
static const size_t kBounceBufferSize = 1024 * 1024;


// Heap allocated path buffer: these functions may run in deep call chains
// (page faults, VM I/O), so keep large buffers off the kernel stack.
struct PathBuffer {
	PathBuffer() : fBuffer((char*)malloc(B_PATH_NAME_LENGTH)) {}
	~PathBuffer() { free(fBuffer); }
	operator char*() const { return fBuffer; }
	size_t Size() const { return fBuffer != NULL ? B_PATH_NAME_LENGTH : 0; }
	char* fBuffer;
};


Inode::Inode(Volume* volume, ino_t id, Inode* parent, const char* name,
	bool directory)
	:
	fNextInTable(NULL),
	fVolume(volume),
	fID(id),
	fParent(parent),
	fName(strdup(name)),
	fDirectory(directory),
	fRemoved(false),
	fPublished(false),
	fFirstChild(NULL),
	fNextSibling(NULL),
	fLock("smbfs inode"),
	fInfoTime(0),
	fInfoValid(false),
	fFileCache(NULL),
	fWriters(0),
	fCacheInvalidate(false),
	fCacheResize(false),
	fLastLocalWrite(0),
	fWriterCookies(NULL),
	fWriteBackError(B_OK)
{
}


// The page writer skips pages that are already being written when the cache
// is synced, so writes of ours may still be in flight after file_cache_sync()
// returns. Within this window the size reported by the server must not be
// allowed to shrink the file (and drop those pages).
static const bigtime_t kLocalWriteSettleTime = 10 * 1000000LL;


Inode::~Inode()
{
	DeleteFileCache();
	free(fName);
}


// #pragma mark - file cache


status_t
Inode::CreateFileCache()
{
	if (fDirectory || fFileCache != NULL)
		return B_OK;
	uint64 size;
	{
		MutexLocker locker(fLock);
		size = fInfo.endOfFile;
	}
	fFileCache = file_cache_create(fVolume->ID(), fID, (off_t)size);
	return fFileCache != NULL ? B_OK : B_NO_MEMORY;
}


void
Inode::DeleteFileCache()
{
	if (fFileCache != NULL) {
		file_cache_delete(fFileCache);
		fFileCache = NULL;
	}
}


void
Inode::_SetSize(uint64 size)
{
	{
		MutexLocker locker(fLock);
		fInfo.endOfFile = size;
		fCacheResize = false;
	}
	if (fFileCache != NULL)
		file_cache_set_size(fFileCache, (off_t)size);
}


// Stores attributes received from the server. With kCacheCheck, cached
// data is marked stale if the file changed on the server. The file cache
// itself is only touched by _SyncCache(), which runs from VFS hooks without
// any of our locks held (cache operations can block on page I/O that in turn
// needs the tree lock and the connection).
void
Inode::_ApplyServerInfo(const FileInfo& info, bool keepIdentity,
	cache_action action)
{
	MutexLocker locker(fLock);
	bool changed = fInfoValid && (info.lastWriteTime != fInfo.lastWriteTime
		|| info.endOfFile != fInfo.endOfFile);
	uint32 links = fInfo.numberOfLinks;
	uint64 index = fInfo.indexNumber;
	uint64 localSize = fInfo.endOfFile;
	fInfo = info;
	if (keepIdentity) {
		fInfo.numberOfLinks = links;
		fInfo.indexNumber = index;
	}
	bigtime_t now = SystemTime();
	bool recentlyWritten = fLastLocalWrite != 0
		&& now - fLastLocalWrite < kLocalWriteSettleTime;
	if (fInfoValid && localSize > fInfo.endOfFile
		&& (fWriters > 0 || recentlyWritten || action == kCacheOwnChange)) {
		// Our own writes may not have reached the server yet; keep the
		// local size until things settle.
		fInfo.endOfFile = localSize;
	}
	fInfoTime = now;
	fInfoValid = true;
	if (action == kCacheCheck && changed && !recentlyWritten)
		fCacheInvalidate = true;
	if (action != kCacheIgnore)
		fCacheResize = true;
}


// Applies pending file cache changes. Must only be called from VFS hooks
// (the vnode is referenced, no locks are held, and we are not inside cache
// I/O).
void
Inode::_SyncCache()
{
	if (fFileCache == NULL)
		return;
	bool invalidate, resize;
	uint64 size;
	{
		MutexLocker locker(fLock);
		if (fWriters > 0) {
			// Our own writes are in progress; the size is tracked locally.
			fCacheInvalidate = false;
			fCacheResize = false;
			return;
		}
		invalidate = fCacheInvalidate;
		resize = fCacheResize;
		size = fInfo.endOfFile;
		fCacheInvalidate = false;
		fCacheResize = false;
		if (fLastLocalWrite != 0
			&& SystemTime() - fLastLocalWrite < kLocalWriteSettleTime) {
			// Writes may still be in flight; do not touch the cache size.
			resize = false;
			invalidate = false;
		}
	}
	if (invalidate) {
		Trace("inode %lld changed on the server, dropping cached data\n",
			(long long)fID);
		file_cache_disable(fFileCache);
		file_cache_set_size(fFileCache, (off_t)size);
		file_cache_enable(fFileCache);
	} else if (resize)
		file_cache_set_size(fFileCache, (off_t)size);
}


// #pragma mark - tree


status_t
Inode::SetName(const char* name)
{
	char* newName = strdup(name);
	if (newName == NULL)
		return B_NO_MEMORY;
	free(fName);
	fName = newName;
	return B_OK;
}


void
Inode::AddChild(Inode* child)
{
	child->fNextSibling = fFirstChild;
	fFirstChild = child;
}


void
Inode::RemoveChild(Inode* child)
{
	Inode** link = &fFirstChild;
	while (*link != NULL) {
		if (*link == child) {
			*link = child->fNextSibling;
			child->fNextSibling = NULL;
			return;
		}
		link = &(*link)->fNextSibling;
	}
}


Inode*
Inode::FindChild(const char* name) const
{
	for (Inode* child = fFirstChild; child != NULL;
			child = child->fNextSibling) {
		if (strcmp(child->fName, name) == 0)
			return child;
	}
	return NULL;
}


// #pragma mark - attributes


void
Inode::UpdateInfo(const FileInfo& info)
{
	_ApplyServerInfo(info, false, kCacheCheck);
}


void
Inode::InvalidateInfo()
{
	MutexLocker locker(fLock);
	fInfoTime = 0;
}


bool
Inode::InfoIsFresh() const
{
	if (!fInfoValid)
		return false;
	return SystemTime() - fInfoTime < fVolume->Options().cacheTimeout;
}


status_t
Inode::RefreshInfo(bool force)
{
	if (!force && InfoIsFresh())
		return B_OK;

	PathBuffer path;
	status_t status = fVolume->BuildPath(this, path, path.Size());
	if (status != B_OK)
		return status;

	FileInfo info;
	status = fVolume->GetConnection()->QueryPathInfo(path, info);
	if (status != B_OK)
		return status;
	UpdateInfo(info);
	return B_OK;
}


status_t
Inode::ReadStat(struct stat* stat)
{
	status_t status = RefreshInfo(false);
	_SyncCache();
	if (status != B_OK && !fInfoValid)
		return status;

	MutexLocker locker(fLock);
	memset(stat, 0, sizeof(*stat));
	stat->st_dev = fVolume->ID();
	stat->st_ino = fID;
	stat->st_mode = fVolume->ModeFor(fInfo);
	stat->st_nlink = fInfo.numberOfLinks > 0 ? fInfo.numberOfLinks : 1;
	stat->st_uid = fVolume->Options().uid;
	stat->st_gid = fVolume->Options().gid;
	stat->st_size = fDirectory ? 0 : (off_t)fInfo.endOfFile;
	stat->st_blksize = 65536;
	stat->st_blocks = (blkcnt_t)((fInfo.allocationSize + 511) / 512);
	FileTimeToTimespec(fInfo.lastAccessTime, stat->st_atim);
	FileTimeToTimespec(fInfo.lastWriteTime, stat->st_mtim);
	FileTimeToTimespec(fInfo.changeTime, stat->st_ctim);
	FileTimeToTimespec(fInfo.creationTime, stat->st_crtim);
	return B_OK;
}


status_t
Inode::WriteStat(const struct stat* stat, uint32 mask)
{
	if (fVolume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	_SyncCache();

	PathBuffer path;
	status_t status = fVolume->BuildPath(this, path, path.Size());
	if (status != B_OK)
		return status;

	Connection* connection = fVolume->GetConnection();

	if ((mask & B_STAT_SIZE) != 0 && !fDirectory) {
		if (fFileCache != NULL)
			file_cache_sync(fFileCache);
		status = connection->SetPathEndOfFile(path, (uint64)stat->st_size);
		if (status != B_OK)
			return status;
		_SetSize((uint64)stat->st_size);
	}

	uint32 timeMask = B_STAT_MODIFICATION_TIME | B_STAT_ACCESS_TIME
		| B_STAT_CREATION_TIME;
	if ((mask & (timeMask | B_STAT_MODE)) != 0) {
		uint64 creationTime = 0, accessTime = 0, writeTime = 0;
		if ((mask & B_STAT_MODIFICATION_TIME) != 0)
			writeTime = TimespecToFileTime(stat->st_mtim);
		if ((mask & B_STAT_ACCESS_TIME) != 0)
			accessTime = TimespecToFileTime(stat->st_atim);
		if ((mask & B_STAT_CREATION_TIME) != 0)
			creationTime = TimespecToFileTime(stat->st_crtim);

		uint32 attributes = 0;
		if ((mask & B_STAT_MODE) != 0) {
			RefreshInfo(false);
			MutexLocker locker(fLock);
			attributes = fInfo.attributes & ~(uint32)FILE_ATTRIBUTE_NORMAL;
			bool wantReadOnly = (stat->st_mode & S_IWUSR) == 0;
			if (wantReadOnly)
				attributes |= FILE_ATTRIBUTE_READONLY;
			else
				attributes &= ~(uint32)FILE_ATTRIBUTE_READONLY;
			attributes &= ~(uint32)FILE_ATTRIBUTE_DIRECTORY;
			if (attributes == 0)
				attributes = FILE_ATTRIBUTE_NORMAL;
		}

		if (writeTime != 0 || accessTime != 0 || creationTime != 0
			|| attributes != 0) {
			// Copy tools (Tracker, cp -p) set permissions and times while
			// the file is still open and its data may only be in the file
			// cache. Write that data first: once the file is read-only the
			// server refuses to open it for writing, and data arriving after
			// the new times makes the server stamp the current time. A
			// failure here is reported by fsync() and close().
			if (fFileCache != NULL && !fDirectory)
				file_cache_sync(fFileCache);

			// Prefer an open writable handle: times set through the handle
			// that wrote the data are kept when that handle is closed.
			FileCookie handle;
			FileCookie* owner = _BorrowWriteHandle(handle);
			status = B_ERROR;
			if (owner != NULL) {
				status = connection->SetBasicInfo(handle.id, creationTime,
					accessTime, writeTime, 0, attributes);
				_ReturnWriteHandle(owner);
			}
			if (status != B_OK) {
				status = connection->SetPathBasicInfo(path, creationTime,
					accessTime, writeTime, 0, attributes);
			}
			if (status != B_OK)
				return status;
		}
	}

	InvalidateInfo();
	ino_t parentID;
	{
		ReadLocker locker(fVolume->TreeLock());
		parentID = fParent != NULL ? fParent->ID() : fID;
	}
	notify_stat_changed(fVolume->ID(), parentID, fID, mask);
	return B_OK;
}


status_t
Inode::Access(int mode)
{
	if ((mode & W_OK) != 0) {
		if (fVolume->IsReadOnly())
			return B_READ_ONLY_DEVICE;
		RefreshInfo(false);
		MutexLocker locker(fLock);
		if (fInfoValid && fInfo.IsReadOnly() && !fDirectory)
			return B_PERMISSION_DENIED;
	}
	return B_OK;
}


// #pragma mark - files


status_t
Inode::_OpenHandle(FileCookie* cookie, bool cacheCheck)
{
	PathBuffer path;
	status_t status = fVolume->BuildPath(this, path, path.Size());
	if (status != B_OK)
		return status;

	Connection* connection = fVolume->GetConnection();
	FileInfo info;
	status = connection->Create(path, cookie->desiredAccess, FILE_SHARE_ALL,
		FILE_OPEN, cookie->createOptions, 0, cookie->id, &info);
	if (status != B_OK) {
		cookie->id.Invalidate();
		return status;
	}
	cookie->generation = connection->Generation();
	// The CREATE response carries no link count or index number; keep the
	// cached values for those.
	_ApplyServerInfo(info, true, cacheCheck ? kCacheCheck : kCacheIgnore);
	return B_OK;
}


void
Inode::_AttachCookie(FileCookie* cookie)
{
	cookie->attached = true;
	if ((cookie->desiredAccess & FILE_WRITE_DATA) != 0) {
		MutexLocker locker(fLock);
		fWriters++;
		cookie->nextWriter = fWriterCookies;
		fWriterCookies = cookie;
	}
}


// Finds an open, writable handle of this file and copies it into "handle".
// The returned owner cookie must be given back with _ReturnWriteHandle();
// until then Close() does not close the handle. Returns NULL if there is no
// usable writer.
//
// Write-back must not open the file again when a writer exists: copy tools
// make a file read-only before closing it, and the server then refuses new
// opens for writing, while an existing handle keeps its access. Data still
// in the file cache would be lost.
FileCookie*
Inode::_BorrowWriteHandle(FileCookie& handle)
{
	uint32 generation = fVolume->GetConnection()->Generation();
	MutexLocker locker(fLock);
	for (FileCookie* cookie = fWriterCookies; cookie != NULL;
			cookie = cookie->nextWriter) {
		if (cookie->id.IsValid() && cookie->generation == generation) {
			cookie->borrowers++;
			handle.id = cookie->id;
			handle.generation = cookie->generation;
			handle.desiredAccess = cookie->desiredAccess;
			handle.createOptions = cookie->createOptions;
			handle.openMode = cookie->openMode;
			return cookie;
		}
	}
	return NULL;
}


void
Inode::_ReturnWriteHandle(FileCookie* owner)
{
	MutexLocker locker(fLock);
	owner->borrowers--;
}


// Unregisters an open writer, then waits until no write-back uses its
// handle any more, so that it can be closed.
void
Inode::_RemoveWriter(FileCookie* cookie)
{
	MutexLocker locker(fLock);
	for (FileCookie** link = &fWriterCookies; *link != NULL;
			link = &(*link)->nextWriter) {
		if (*link == cookie) {
			*link = cookie->nextWriter;
			break;
		}
	}
	cookie->nextWriter = NULL;
	while (cookie->borrowers > 0) {
		// a write-back of the page writer is in progress
		locker.Unlock();
		Snooze(1000);
		locker.Lock();
	}
}


// Returns (and clears) the first write-back failure not reported yet.
status_t
Inode::_TakeWriteBackError()
{
	MutexLocker locker(fLock);
	status_t error = fWriteBackError;
	fWriteBackError = B_OK;
	return error;
}


status_t
Inode::_EnsureOpen(FileCookie* cookie)
{
	Connection* connection = fVolume->GetConnection();
	if (cookie->id.IsValid() && connection->IsConnected()
		&& cookie->generation == connection->Generation()) {
		return B_OK;
	}
	// The connection was re-established (or never opened); reopen. This
	// runs from I/O paths, so the file cache must not be touched here.
	cookie->id.Invalidate();
	return _OpenHandle(cookie, false);
}


status_t
Inode::Open(int openMode, FileCookie** _cookie)
{
	int accessMode = openMode & O_ACCMODE;
	if (fVolume->IsReadOnly() && accessMode != O_RDONLY)
		return B_READ_ONLY_DEVICE;
	if (fDirectory && accessMode != O_RDONLY)
		return B_IS_A_DIRECTORY;

	FileCookie* cookie = new(std::nothrow) FileCookie;
	if (cookie == NULL)
		return B_NO_MEMORY;
	cookie->openMode = openMode;
	cookie->directory = fDirectory;

	uint32 access = FILE_READ_ATTRIBUTES;
	if (fDirectory) {
		access |= FILE_LIST_DIRECTORY;
		cookie->createOptions = FILE_DIRECTORY_FILE;
	} else {
		if (accessMode == O_RDONLY || accessMode == O_RDWR)
			access |= FILE_READ_DATA;
		if (accessMode == O_WRONLY || accessMode == O_RDWR) {
			access |= FILE_WRITE_DATA | FILE_APPEND_DATA
				| FILE_WRITE_ATTRIBUTES;
		}
		cookie->createOptions = FILE_NON_DIRECTORY_FILE;
	}
	cookie->desiredAccess = access;

	status_t status;
	if ((openMode & O_TRUNC) != 0 && !fDirectory) {
		PathBuffer path;
		status = fVolume->BuildPath(this, path, path.Size());
		if (status == B_OK) {
			Connection* connection = fVolume->GetConnection();
			FileInfo info;
			status = connection->Create(path, access, FILE_SHARE_ALL,
				FILE_OVERWRITE, cookie->createOptions, FILE_ATTRIBUTE_NORMAL,
				cookie->id, &info);
			if (status == B_OK) {
				cookie->generation = connection->Generation();
				_ApplyServerInfo(info, true, kCacheOwnChange);
				_SetSize(0);
				ino_t parentID;
				{
					ReadLocker locker(fVolume->TreeLock());
					parentID = fParent != NULL ? fParent->ID() : fID;
				}
				notify_stat_changed(fVolume->ID(), parentID, fID,
					B_STAT_SIZE | B_STAT_MODIFICATION_TIME);
			}
		}
	} else
		status = _OpenHandle(cookie, true);

	if (status != B_OK) {
		delete cookie;
		return status;
	}
	// Apply any pending invalidation before registering the writer, so that
	// data changed on the server is dropped before it is read again.
	_SyncCache();
	_AttachCookie(cookie);
	*_cookie = cookie;
	return B_OK;
}


status_t
Inode::Close(FileCookie* cookie)
{
	bool writer = cookie->attached
		&& (cookie->desiredAccess & FILE_WRITE_DATA) != 0;
	status_t result = B_OK;
	if (writer && fFileCache != NULL) {
		// Push pending data to the server while this handle is still open
		// (write-back borrows it, see _BorrowWriteHandle()).
		result = file_cache_sync(fFileCache);
	}
	if (writer)
		_RemoveWriter(cookie);

	Connection* connection = fVolume->GetConnection();
	FileInfo info;
	bool haveInfo = false;
	if (cookie->id.IsValid() && connection->IsConnected()
		&& cookie->generation == connection->Generation()) {
		haveInfo = connection->Close(cookie->id, &info) == B_OK && !fDirectory;
	}
	cookie->id.Invalidate();

	if (writer) {
		MutexLocker locker(fLock);
		if (fWriters > 0)
			fWriters--;
	}
	if (haveInfo) {
		// Temporary handles are closed from within cache I/O; never touch
		// the cache for those.
		_ApplyServerInfo(info, true, !cookie->attached ? kCacheIgnore
			: (writer ? kCacheOwnChange : kCacheIgnore));
	}
	if (cookie->attached) {
		_SyncCache();
		if (writer) {
			// Make sure the next open sees the server's view of the file.
			InvalidateInfo();
		}
	}
	if (writer) {
		// Report data that could not be written, instead of losing it
		// silently.
		status_t error = _TakeWriteBackError();
		if (result == B_OK)
			result = error;
	}
	return result;
}


status_t
Inode::_ReadDirect(FileCookie* cookie, off_t pos, void* buffer,
	size_t* _length)
{
	Connection* connection = fVolume->GetConnection();
	status_t status = B_OK;
	for (int attempt = 0; attempt < 2; attempt++) {
		status = _EnsureOpen(cookie);
		if (status != B_OK)
			return status;
		size_t bytesRead = 0;
		status = connection->Read(cookie->id, (uint64)pos, buffer, *_length,
			&bytesRead);
		if (status == B_OK) {
			*_length = bytesRead;
			return B_OK;
		}
		if (status != SMB2_DISCONNECTED)
			break;
	}
	*_length = 0;
	return status;
}


status_t
Inode::_WriteDirect(FileCookie* cookie, off_t pos, const void* buffer,
	size_t* _length)
{
	Connection* connection = fVolume->GetConnection();
	status_t status = B_OK;
	for (int attempt = 0; attempt < 2; attempt++) {
		status = _EnsureOpen(cookie);
		if (status != B_OK)
			return status;
		size_t written = 0;
		status = connection->Write(cookie->id, (uint64)pos, buffer, *_length,
			&written);
		if (status == B_OK) {
			*_length = written;
			MutexLocker locker(fLock);
			if ((uint64)pos + written > fInfo.endOfFile)
				fInfo.endOfFile = (uint64)pos + written;
			fInfo.lastWriteTime = ((uint64)RealTimeUsecs()
				+ 11644473600000000ULL) * 10;
			fLastLocalWrite = SystemTime();
			return B_OK;
		}
		if (status != SMB2_DISCONNECTED)
			break;
	}
	*_length = 0;
	return status;
}


status_t
Inode::Read(FileCookie* cookie, off_t pos, void* buffer, size_t* _length)
{
	if (fDirectory)
		return B_IS_A_DIRECTORY;
	if (pos < 0)
		return B_BAD_VALUE;
	if (*_length == 0)
		return B_OK;

	if (fFileCache != NULL) {
		_SyncCache();
		return file_cache_read(fFileCache, cookie, pos, buffer, _length);
	}

	if (!IS_USER_ADDRESS(buffer))
		return _ReadDirect(cookie, pos, buffer, _length);

	size_t total = *_length;
	size_t bounceSize = total < kBounceBufferSize ? total : kBounceBufferSize;
	uint8* bounce = (uint8*)malloc(bounceSize);
	if (bounce == NULL)
		return B_NO_MEMORY;

	size_t done = 0;
	status_t status = B_OK;
	while (done < total) {
		size_t chunk = total - done;
		if (chunk > bounceSize)
			chunk = bounceSize;
		status = _ReadDirect(cookie, pos + done, bounce, &chunk);
		if (status != B_OK)
			break;
		if (chunk == 0)
			break;
		if (user_memcpy((uint8*)buffer + done, bounce, chunk) != B_OK) {
			status = B_BAD_ADDRESS;
			break;
		}
		done += chunk;
		if (chunk < bounceSize)
			break;
	}
	free(bounce);
	if (done > 0)
		status = B_OK;
	*_length = done;
	return status;
}


status_t
Inode::Write(FileCookie* cookie, off_t pos, const void* buffer,
	size_t* _length)
{
	if (fDirectory)
		return B_IS_A_DIRECTORY;
	if (fVolume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (*_length == 0)
		return B_OK;

	if ((cookie->openMode & O_APPEND) != 0) {
		RefreshInfo(false);
		MutexLocker locker(fLock);
		pos = (off_t)fInfo.endOfFile;
	}
	if (pos < 0)
		return B_BAD_VALUE;

	if (fFileCache != NULL) {
		_SyncCache();
		uint64 end = (uint64)pos + *_length;
		bool extend = false;
		{
			MutexLocker locker(fLock);
			if (end > fInfo.endOfFile)
				extend = true;
			fInfo.lastWriteTime = ((uint64)RealTimeUsecs()
				+ 11644473600000000ULL) * 10;
			fLastLocalWrite = SystemTime();
		}
		if (extend)
			_SetSize(end);
		return file_cache_write(fFileCache, cookie, pos, buffer, _length);
	}

	if (!IS_USER_ADDRESS(buffer))
		return _WriteDirect(cookie, pos, buffer, _length);

	size_t total = *_length;
	size_t bounceSize = total < kBounceBufferSize ? total : kBounceBufferSize;
	uint8* bounce = (uint8*)malloc(bounceSize);
	if (bounce == NULL)
		return B_NO_MEMORY;

	size_t done = 0;
	status_t status = B_OK;
	while (done < total) {
		size_t chunk = total - done;
		if (chunk > bounceSize)
			chunk = bounceSize;
		if (user_memcpy(bounce, (const uint8*)buffer + done, chunk) != B_OK) {
			status = B_BAD_ADDRESS;
			break;
		}
		size_t written = chunk;
		status = _WriteDirect(cookie, pos + done, bounce, &written);
		if (status != B_OK)
			break;
		done += written;
		if (written < chunk)
			break;
	}
	free(bounce);
	if (done > 0)
		status = B_OK;
	*_length = done;
	return status;
}


status_t
Inode::ReadPages(FileCookie* cookie, off_t pos, const iovec* vecs,
	size_t count, size_t* _numBytes)
{
	FileCookie temporary;
	bool useTemporary = cookie == NULL || !cookie->id.IsValid()
		|| (cookie->desiredAccess & FILE_READ_DATA) == 0;
	if (useTemporary) {
		temporary.desiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
		temporary.createOptions = FILE_NON_DIRECTORY_FILE;
		cookie = &temporary;
	}

	size_t total = 0;
	status_t status = B_OK;
	for (size_t i = 0; i < count; i++) {
		size_t length = vecs[i].iov_len;
		status = _ReadDirect(cookie, pos, vecs[i].iov_base, &length);
		if (status != B_OK)
			break;
		total += length;
		pos += length;
		if (length < vecs[i].iov_len) {
			// Short read: zero fill the rest of the request (EOF).
			memset((uint8*)vecs[i].iov_base + length, 0,
				vecs[i].iov_len - length);
			for (size_t j = i + 1; j < count; j++)
				memset(vecs[j].iov_base, 0, vecs[j].iov_len);
			break;
		}
	}

	if (useTemporary && temporary.id.IsValid())
		Close(&temporary);

	if (total > 0)
		status = B_OK;
	*_numBytes = total;
	return status;
}


status_t
Inode::WritePages(FileCookie* cookie, off_t pos, const iovec* vecs,
	size_t count, size_t* _numBytes)
{
	if (fVolume->IsReadOnly())
		return B_READ_ONLY_DEVICE;

	// The page writer and file_cache_sync() call us without a cookie. Use an
	// open writable handle then, and only open the file again if there is
	// none (see _BorrowWriteHandle()).
	FileCookie temporary;
	FileCookie* owner = NULL;
	smb2::FileId borrowedId;
	bool useTemporary = cookie == NULL || !cookie->id.IsValid()
		|| (cookie->desiredAccess & FILE_WRITE_DATA) == 0;
	if (useTemporary) {
		owner = _BorrowWriteHandle(temporary);
		if (owner == NULL) {
			temporary.desiredAccess = FILE_WRITE_DATA | FILE_READ_ATTRIBUTES
				| FILE_WRITE_ATTRIBUTES;
			temporary.createOptions = FILE_NON_DIRECTORY_FILE;
		}
		borrowedId = temporary.id;
		cookie = &temporary;
	}

	// Writes from the VM must not extend the file beyond its size. The size
	// is maintained locally; do not refresh it here (this runs inside cache
	// I/O).
	uint64 fileSize;
	{
		MutexLocker locker(fLock);
		fileSize = fInfo.endOfFile;
	}

	size_t total = 0;
	status_t status = B_OK;
	for (size_t i = 0; i < count; i++) {
		size_t length = vecs[i].iov_len;
		if ((uint64)pos >= fileSize) {
			total += length;
			continue;
		}
		if ((uint64)pos + length > fileSize)
			length = (size_t)(fileSize - pos);
		size_t written = length;
		status = _WriteDirect(cookie, pos, vecs[i].iov_base, &written);
		if (status != B_OK)
			break;
		total += vecs[i].iov_len;
		pos += vecs[i].iov_len;
	}

	if (owner != NULL)
		_ReturnWriteHandle(owner);
	// Close what we opened ourselves: a temporary handle, or the reopened
	// copy of a borrowed one after a reconnect (never the borrowed handle).
	if (useTemporary && temporary.id.IsValid()
		&& (owner == NULL || temporary.id.persistent != borrowedId.persistent
			|| temporary.id.volatileId != borrowedId.volatileId)) {
		Close(&temporary);
	}

	if (status != B_OK) {
		Log("writing data of inode %lld (offset %lld) to the server failed: "
			"%s\n", (long long)fID, (long long)pos, strerror(status));
		MutexLocker locker(fLock);
		if (fWriteBackError == B_OK)
			fWriteBackError = status;
	}

	if (total > 0)
		status = B_OK;
	*_numBytes = total;
	return status;
}


status_t
Inode::Sync(FileCookie* cookie)
{
	if (fFileCache != NULL) {
		_SyncCache();
		status_t status = file_cache_sync(fFileCache);
		if (status != B_OK)
			return status;
	}
	status_t error = _TakeWriteBackError();
	if (error != B_OK)
		return error;
	if (cookie == NULL || !cookie->id.IsValid())
		return B_OK;
	Connection* connection = fVolume->GetConnection();
	if (!connection->IsConnected()
		|| cookie->generation != connection->Generation()) {
		return B_OK;
	}
	return connection->Flush(cookie->id);
}


// #pragma mark - directories


status_t
Inode::_EnsureDirOpen(DirCookie* cookie)
{
	Connection* connection = fVolume->GetConnection();
	if (cookie->id.IsValid() && connection->IsConnected()
		&& cookie->generation == connection->Generation()) {
		return B_OK;
	}

	PathBuffer path;
	status_t status = fVolume->BuildPath(this, path, path.Size());
	if (status != B_OK)
		return status;

	cookie->id.Invalidate();
	status = connection->Create(path, FILE_LIST_DIRECTORY
		| FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, FILE_OPEN, FILE_DIRECTORY_FILE,
		0, cookie->id);
	if (status != B_OK)
		return status;
	cookie->generation = connection->Generation();
	// A new handle starts a new enumeration.
	cookie->restart = true;
	return B_OK;
}


status_t
Inode::OpenDir(DirCookie** _cookie)
{
	if (!fDirectory)
		return B_NOT_A_DIRECTORY;

	DirCookie* cookie = new(std::nothrow) DirCookie;
	if (cookie == NULL)
		return B_NO_MEMORY;

	status_t status = _EnsureDirOpen(cookie);
	if (status != B_OK) {
		delete cookie;
		return status;
	}
	*_cookie = cookie;
	return B_OK;
}


status_t
Inode::CloseDir(DirCookie* cookie)
{
	Connection* connection = fVolume->GetConnection();
	if (cookie->id.IsValid() && connection->IsConnected()
		&& cookie->generation == connection->Generation()) {
		connection->Close(cookie->id);
	}
	cookie->id.Invalidate();
	return B_OK;
}


status_t
Inode::RewindDir(DirCookie* cookie)
{
	cookie->synthetic = 0;
	cookie->restart = true;
	cookie->offset = 0;
	cookie->bufferLength = 0;
	cookie->done = false;
	return B_OK;
}


status_t
Inode::_FillDirectory(DirCookie* cookie)
{
	if (cookie->buffer == NULL) {
		cookie->buffer = (uint8*)malloc(kDirectoryBufferSize);
		if (cookie->buffer == NULL)
			return B_NO_MEMORY;
		cookie->bufferSize = kDirectoryBufferSize;
	}

	status_t status = _EnsureDirOpen(cookie);
	if (status != B_OK)
		return status;

	Connection* connection = fVolume->GetConnection();
	size_t length = 0;
	status = connection->QueryDirectory(cookie->id, "*",
		cookie->restart ? SMB2_RESTART_SCANS : 0, cookie->buffer,
		cookie->bufferSize, &length);
	cookie->restart = false;
	cookie->offset = 0;
	cookie->bufferLength = 0;
	if (status == B_ENTRY_NOT_FOUND) {
		cookie->done = true;
		return B_OK;
	}
	if (status != B_OK)
		return status;
	cookie->bufferLength = length;
	if (length == 0)
		cookie->done = true;
	return B_OK;
}


status_t
Inode::ReadDir(DirCookie* cookie, struct dirent* buffer, size_t bufferSize,
	uint32* _num)
{
	uint32 maxCount = *_num;
	uint32 count = 0;
	size_t used = 0;
	status_t status = B_OK;

	while (count < maxCount) {
		const char* name;
		char nameBuffer[B_FILE_NAME_LENGTH];
		ino_t id;

		if (cookie->synthetic == 0) {
			name = ".";
			id = fID;
		} else if (cookie->synthetic == 1) {
			name = "..";
			ReadLocker locker(fVolume->TreeLock());
			id = fParent != NULL ? fParent->ID() : fID;
		} else {
			if (cookie->offset >= cookie->bufferLength) {
				if (cookie->done)
					break;
				status = _FillDirectory(cookie);
				if (status != B_OK)
					break;
				if (cookie->done || cookie->bufferLength == 0)
					break;
			}

			// Parse one FileIdFullDirectoryInformation entry.
			const size_t kFixedSize = 80;
			if (cookie->offset + kFixedSize > cookie->bufferLength) {
				cookie->done = true;
				break;
			}
			const uint8* entry = cookie->buffer + cookie->offset;
			uint32 nextEntryOffset = LoadLE32(entry);
			uint32 nameLength = LoadLE32(entry + 60);
			if (cookie->offset + kFixedSize + nameLength
					> cookie->bufferLength) {
				cookie->done = true;
				break;
			}

			FileInfo info;
			info.creationTime = LoadLE64(entry + 8);
			info.lastAccessTime = LoadLE64(entry + 16);
			info.lastWriteTime = LoadLE64(entry + 24);
			info.changeTime = LoadLE64(entry + 32);
			info.endOfFile = LoadLE64(entry + 40);
			info.allocationSize = LoadLE64(entry + 48);
			info.attributes = LoadLE32(entry + 56);
			info.indexNumber = LoadLE64(entry + 72);
			info.numberOfLinks = 1;

			ssize_t utf8Length = Utf16LEToUtf8(entry + kFixedSize, nameLength,
				nameBuffer, sizeof(nameBuffer));

			// Advance now; the entry is consumed even if skipped.
			size_t nextOffset = nextEntryOffset != 0
				? cookie->offset + nextEntryOffset : cookie->bufferLength;
			if (nextOffset <= cookie->offset)
				nextOffset = cookie->bufferLength;

			if (utf8Length <= 0 || strcmp(nameBuffer, ".") == 0
				|| strcmp(nameBuffer, "..") == 0
				|| strchr(nameBuffer, '/') != NULL) {
				cookie->offset = nextOffset;
				continue;
			}

			Inode* child = fVolume->FindOrCreateChild(this, nameBuffer, &info);
			if (child == NULL) {
				status = B_NO_MEMORY;
				break;
			}
			name = nameBuffer;
			id = child->ID();

			size_t nameSize = strlen(name) + 1;
			size_t recordLength = (offsetof(struct dirent, d_name) + nameSize
				+ 7) & ~(size_t)7;
			if (used + recordLength > bufferSize) {
				if (count == 0)
					status = B_BUFFER_OVERFLOW;
				break;
			}
			cookie->offset = nextOffset;

			struct dirent* dirent = (struct dirent*)((uint8*)buffer + used);
			dirent->d_dev = fVolume->ID();
			dirent->d_pdev = 0;
			dirent->d_ino = id;
			dirent->d_pino = 0;
			dirent->d_reclen = (unsigned short)recordLength;
			memcpy(dirent->d_name, name, nameSize);
			used += recordLength;
			count++;
			continue;
		}

		// synthetic entries
		size_t nameSize = strlen(name) + 1;
		size_t recordLength = (offsetof(struct dirent, d_name) + nameSize + 7)
			& ~(size_t)7;
		if (used + recordLength > bufferSize) {
			if (count == 0)
				status = B_BUFFER_OVERFLOW;
			break;
		}
		struct dirent* dirent = (struct dirent*)((uint8*)buffer + used);
		dirent->d_dev = fVolume->ID();
		dirent->d_pdev = 0;
		dirent->d_ino = id;
		dirent->d_pino = 0;
		dirent->d_reclen = (unsigned short)recordLength;
		memcpy(dirent->d_name, name, nameSize);
		used += recordLength;
		count++;
		cookie->synthetic++;
	}

	if (count > 0)
		status = B_OK;
	*_num = count;
	return status;
}
