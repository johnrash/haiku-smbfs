/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef SMBFS_INODE_H
#define SMBFS_INODE_H

#include <dirent.h>
#include <fs_interface.h>
#include <sys/stat.h>

#include "../smb2/Connection.h"
#include "../smb2/Platform.h"


class Volume;


struct FileCookie {
	smb2::FileId		id;
	uint32				generation;
	int					openMode;
	uint32				desiredAccess;
	uint32				createOptions;
	bool				directory;
	bool				attached;	// registered with the inode (not temporary)
	FileCookie*			nextWriter;	// the inode's open writers (inode lock)
	int32				borrowers;	// write-backs using this handle (inode lock)

	FileCookie()
		:
		generation(0),
		openMode(0),
		desiredAccess(0),
		createOptions(0),
		directory(false),
		attached(false),
		nextWriter(NULL),
		borrowers(0)
	{
	}
};


struct DirCookie {
	smb2::FileId		id;
	uint32				generation;
	uint8*				buffer;
	size_t				bufferSize;
	size_t				bufferLength;
	size_t				offset;
	bool				restart;
	bool				done;
	int					synthetic;	// 0: ".", 1: "..", 2: server entries

	DirCookie()
		:
		generation(0),
		buffer(NULL),
		bufferSize(0),
		bufferLength(0),
		offset(0),
		restart(true),
		done(false),
		synthetic(0)
	{
	}
};


class Inode {
public:
								Inode(Volume* volume, ino_t id, Inode* parent,
									const char* name, bool directory);
								~Inode();

			status_t			InitCheck() const
									{ return fName != NULL ? B_OK : B_NO_MEMORY; }

			Volume*				GetVolume() const { return fVolume; }
			ino_t				ID() const { return fID; }
			Inode*				Parent() const { return fParent; }
			const char*			Name() const { return fName; }
			bool				IsDirectory() const { return fDirectory; }
			mode_t				Type() const
									{ return fDirectory ? S_IFDIR : S_IFREG; }

			bool				IsRemoved() const { return fRemoved; }
			void				MarkRemoved() { fRemoved = true; }
			bool				IsPublished() const { return fPublished; }
			void				SetPublished(bool published)
									{ fPublished = published; }

			// tree structure (protected by the volume's tree lock)
			status_t			SetName(const char* name);
			void				SetParent(Inode* parent) { fParent = parent; }
			void				AddChild(Inode* child);
			void				RemoveChild(Inode* child);
			Inode*				FindChild(const char* name) const;
			Inode*				FirstChild() const { return fFirstChild; }
			Inode*				NextSibling() const { return fNextSibling; }

			// file cache (VM integration, needed for mmap/exec)
			status_t			CreateFileCache();
			void				DeleteFileCache();
			void*				FileCache() const { return fFileCache; }

			// attribute cache
			void				UpdateInfo(const smb2::FileInfo& info);
			void				InvalidateInfo();
			bool				InfoIsFresh() const;
			status_t			RefreshInfo(bool force);
			status_t			ReadStat(struct stat* stat);
			status_t			WriteStat(const struct stat* stat,
									uint32 mask);
			status_t			Access(int mode);
			smb2::FileInfo		Info() const { return fInfo; }

			// file operations
			status_t			Open(int openMode, FileCookie** _cookie);
			void				AttachCookie(FileCookie* cookie)
									{ _AttachCookie(cookie); }
			status_t			Close(FileCookie* cookie);
			status_t			Read(FileCookie* cookie, off_t pos,
									void* buffer, size_t* _length);
			status_t			Write(FileCookie* cookie, off_t pos,
									const void* buffer, size_t* _length);
			status_t			ReadPages(FileCookie* cookie, off_t pos,
									const iovec* vecs, size_t count,
									size_t* _numBytes);
			status_t			WritePages(FileCookie* cookie, off_t pos,
									const iovec* vecs, size_t count,
									size_t* _numBytes);
			status_t			Sync(FileCookie* cookie);

			// directory operations
			status_t			OpenDir(DirCookie** _cookie);
			status_t			CloseDir(DirCookie* cookie);
			status_t			ReadDir(DirCookie* cookie,
									struct dirent* buffer, size_t bufferSize,
									uint32* _num);
			status_t			RewindDir(DirCookie* cookie);

			Inode*				fNextInTable;

private:
	friend class Volume;

			enum cache_action {
				kCacheIgnore,		// never touch the file cache
				kCacheOwnChange,	// the change was made by us
				kCacheCheck			// drop cached data if changed remotely
			};

			status_t			_EnsureOpen(FileCookie* cookie);
			status_t			_OpenHandle(FileCookie* cookie,
									bool cacheCheck);
			void				_ApplyServerInfo(const smb2::FileInfo& info,
									bool keepIdentity, cache_action action);
			void				_SyncCache();
			void				_SetSize(uint64 size);
			void				_AttachCookie(FileCookie* cookie);
			FileCookie*			_BorrowWriteHandle(FileCookie& handle);
			void				_ReturnWriteHandle(FileCookie* owner);
			void				_RemoveWriter(FileCookie* cookie);
			status_t			_TakeWriteBackError();
			status_t			_EnsureDirOpen(DirCookie* cookie);
			status_t			_FillDirectory(DirCookie* cookie);
			status_t			_ReadDirect(FileCookie* cookie, off_t pos,
									void* buffer, size_t* _length);
			status_t			_WriteDirect(FileCookie* cookie, off_t pos,
									const void* buffer, size_t* _length);

private:
			Volume*				fVolume;
			ino_t				fID;
			Inode*				fParent;
			char*				fName;
			bool				fDirectory;
			bool				fRemoved;
			bool				fPublished;

			Inode*				fFirstChild;
			Inode*				fNextSibling;

			smb2::Mutex			fLock;
			smb2::FileInfo		fInfo;
			bigtime_t			fInfoTime;
			bool				fInfoValid;

			void*				fFileCache;
			int32				fWriters;
			bool				fCacheInvalidate;	// pending, see _SyncCache()
			bool				fCacheResize;
			bigtime_t			fLastLocalWrite;	// our last data write
			FileCookie*			fWriterCookies;		// open writable handles
			status_t			fWriteBackError;	// not yet reported
};


#endif	// SMBFS_INODE_H
