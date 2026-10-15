/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef SMBFS_VOLUME_H
#define SMBFS_VOLUME_H

#include <fs_interface.h>
#include <fs_info.h>
#include <sys/stat.h>

#include "../smb2/Connection.h"
#include "../smb2/Platform.h"


class Inode;


struct MountOptions {
	char				server[256];
	char				share[256];
	char				user[256];
	char				password[256];
	char				domain[256];
	char				workstation[64];
	uint16				port;
	uid_t				uid;
	gid_t				gid;
	mode_t				fileMode;
	mode_t				directoryMode;
	bool				sign;
	bool				seal;
	bool				readOnly;
	uint16				minDialect;
	uint16				maxDialect;
	bigtime_t			cacheTimeout;
	bigtime_t			requestTimeout;
	bool				trace;
};


class Volume {
public:
								Volume(fs_volume* fsVolume);
								~Volume();

			status_t			Mount(const char* args, uint32 flags);
			status_t			Unmount();

			fs_volume*			FSVolume() const { return fFSVolume; }
			dev_t				ID() const { return fFSVolume->id; }
			smb2::Connection*	GetConnection() const { return fConnection; }
			const MountOptions&	Options() const { return fOptions; }
			Inode*				Root() const { return fRoot; }
			bool				IsReadOnly() const { return fOptions.readOnly; }
			bool				IsUnmounted() const { return fUnmounted; }

			smb2::RWLock&		TreeLock() { return fTreeLock; }

			// inode table
			Inode*				GetInode(ino_t id);
			Inode*				AcquireForVnode(ino_t id);
			status_t			Lookup(Inode* directory, const char* name,
									ino_t* _id);
			Inode*				FindOrCreateChild(Inode* directory,
									const char* name,
									const smb2::FileInfo* info);
			void				DetachInode(Inode* inode);
			void				InodeUnpublished(Inode* inode);
			void				RemoveInode(Inode* inode);

			status_t			BuildPath(Inode* inode, char* buffer,
									size_t bufferSize);
			status_t			BuildChildPath(Inode* directory,
									const char* name, char* buffer,
									size_t bufferSize);

			status_t			ReadFsInfo(struct fs_info* info);

			mode_t				ModeFor(const smb2::FileInfo& info) const;

private:
			status_t			_ParseArguments(const char* args);
			ino_t				_NextID();
			void				_TableInsert(Inode* inode);
			void				_TableRemove(Inode* inode);
			void				_FreeAllInodes();

private:
			fs_volume*			fFSVolume;
			smb2::Connection*	fConnection;
			MountOptions		fOptions;
			Inode*				fRoot;

			smb2::Mutex			fTableLock;
			Inode**				fTable;
			size_t				fTableSize;
			size_t				fTableCount;
			ino_t				fNextID;

			smb2::RWLock		fTreeLock;
			bool				fUnmounted;

public:
			Volume*				fNextZombie;
};


#endif	// SMBFS_VOLUME_H
