/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Haiku kernel file system interface for smbfs.
 */


#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <fs_interface.h>
#include <fs_info.h>
#include <fs_volume.h>
#include <kernel.h>
#include <KernelExport.h>
#include <NodeMonitor.h>
#include <TypeConstants.h>

#include "Inode.h"
#include "MimeTypes.h"
#include "Volume.h"
#include "../smb2/Crypto.h"
#include "../smb2/Platform.h"

using namespace smb2;


#define TRACE(x...) smb2::Trace(x)

// The VFS removes a mount from its tables and calls unmount() before it
// sends the unmount notification, but the root vnode stays reachable by
// (device, inode) afterwards: a process reacting to the notification
// (Tracker closing its windows) can still open the old root via an entry_ref
// and the VFS then calls vnode hooks on it, even after the mount structure
// has been destroyed (fs_volume pointer NULL or dangling). To survive that:
//  - the module stays loaded (B_KEEP_LOADED), so the ops table is valid,
//  - hooks only dereference an fs_volume that is registered as live, and
//    reject vnodes whose private node is the root of an unmounted volume,
//  - unmounted volumes are kept as "zombies" (with their root inode) so that
//    pointer identities stay unique; they are small and never freed.

static smb2::Mutex* sRegistryLock = NULL;
static const int kMaxLiveVolumes = 64;
static Volume* sLiveVolumes[kMaxLiveVolumes];
static Volume* sZombies = NULL;


static void
register_volume(Volume* volume)
{
	smb2::MutexLocker locker(sRegistryLock);
	for (int i = 0; i < kMaxLiveVolumes; i++) {
		if (sLiveVolumes[i] == NULL) {
			sLiveVolumes[i] = volume;
			return;
		}
	}
}


static void
unregister_volume(Volume* volume)
{
	smb2::MutexLocker locker(sRegistryLock);
	for (int i = 0; i < kMaxLiveVolumes; i++) {
		if (sLiveVolumes[i] == volume)
			sLiveVolumes[i] = NULL;
	}
	volume->fNextZombie = sZombies;
	sZombies = volume;
}


// Returns the Volume for a live mount, or NULL if the fs_volume is not (or
// no longer) one of ours, or if the node is the root of an unmounted volume.
static Volume*
live_volume(fs_volume* fsVolume, const void* privateNode)
{
	smb2::MutexLocker locker(sRegistryLock);
	for (Volume* zombie = sZombies; zombie != NULL;
			zombie = zombie->fNextZombie) {
		if (privateNode != NULL && zombie->Root() == privateNode)
			return NULL;
	}
	for (int i = 0; i < kMaxLiveVolumes; i++) {
		Volume* volume = sLiveVolumes[i];
		if (volume != NULL && volume->FSVolume() == fsVolume)
			return volume;
	}
	return NULL;
}


#define GET_VOLUME(fsVolume, node, errorValue) \
	Volume* volume = live_volume(fsVolume, (node) != NULL \
		? (node)->private_node : NULL); \
	if (volume == NULL) \
		return errorValue;

extern fs_volume_ops gSmbfsVolumeOps;
extern fs_vnode_ops gSmbfsVnodeOps;


static status_t
std_ops(int32 op, ...)
{
	switch (op) {
		case B_MODULE_INIT:
			crypto::Init();
			sRegistryLock = new(std::nothrow) smb2::Mutex("smbfs registry");
			if (sRegistryLock == NULL)
				return B_NO_MEMORY;
			return B_OK;
		case B_MODULE_UNINIT:
		{
			// Not reached while the module is kept loaded; free the zombies
			// for the benefit of userland test hosts.
			while (sZombies != NULL) {
				Volume* zombie = sZombies;
				sZombies = zombie->fNextZombie;
				delete zombie;
			}
			delete sRegistryLock;
			sRegistryLock = NULL;
			return B_OK;
		}
		default:
			return B_ERROR;
	}
}


// #pragma mark - volume


static status_t
smbfs_mount(fs_volume* fsVolume, const char* device, uint32 flags,
	const char* args, ino_t* _rootVnodeID)
{
	TRACE("mount(device = %s, flags = %#lx)\n", device != NULL ? device : "-",
		(unsigned long)flags);

	Volume* volume = new(std::nothrow) Volume(fsVolume);
	if (volume == NULL)
		return B_NO_MEMORY;

	// Allow "mount -t smbfs //server/share /mountpoint" style invocations
	// where the device argument carries the UNC path.
	char* combinedArgs = NULL;
	if (device != NULL && (strncmp(device, "//", 2) == 0
			|| strncmp(device, "\\\\", 2) == 0)) {
		size_t length = strlen(device) + 2 + (args != NULL ? strlen(args) : 0);
		combinedArgs = (char*)malloc(length);
		if (combinedArgs == NULL) {
			delete volume;
			return B_NO_MEMORY;
		}
		strlcpy(combinedArgs, device, length);
		strlcat(combinedArgs, " ", length);
		if (args != NULL)
			strlcat(combinedArgs, args, length);
		args = combinedArgs;
	}

	status_t status = volume->Mount(args, flags);
	free(combinedArgs);
	if (status != B_OK) {
		delete volume;
		return status;
	}

	fsVolume->private_volume = volume;
	fsVolume->ops = &gSmbfsVolumeOps;

	Inode* root = volume->Root();
	status = publish_vnode(fsVolume, root->ID(), root, &gSmbfsVnodeOps,
		S_IFDIR, 0);
	if (status != B_OK) {
		delete volume;
		return status;
	}
	root->SetPublished(true);
	register_volume(volume);
	*_rootVnodeID = root->ID();
	return B_OK;
}


static status_t
smbfs_unmount(fs_volume* fsVolume)
{
	GET_VOLUME(fsVolume, (fs_vnode*)NULL, B_OK);
	TRACE("unmount\n");
	volume->Unmount();
	unregister_volume(volume);
	return B_OK;
}


static status_t
smbfs_read_fs_info(fs_volume* fsVolume, struct fs_info* info)
{
	GET_VOLUME(fsVolume, (fs_vnode*)NULL, B_ENTRY_NOT_FOUND);
	return volume->ReadFsInfo(info);
}


static status_t
smbfs_sync(fs_volume* fsVolume)
{
	return B_OK;
}


static status_t
smbfs_get_vnode(fs_volume* fsVolume, ino_t id, fs_vnode* vnode, int* _type,
	uint32* _flags, bool reenter)
{
	GET_VOLUME(fsVolume, (fs_vnode*)NULL, B_ENTRY_NOT_FOUND);
	Inode* inode = volume->AcquireForVnode(id);
	if (inode == NULL) {
		TRACE("get_vnode(%lld): unknown inode\n", (long long)id);
		return B_ENTRY_NOT_FOUND;
	}
	// Regular files get a file cache so that they can be mapped (and so
	// that reads are cached locally). Failure is not fatal: reads and writes
	// then go to the server directly.
	if (!inode->IsDirectory())
		inode->CreateFileCache();

	vnode->private_node = inode;
	vnode->ops = &gSmbfsVnodeOps;
	*_type = inode->Type();
	*_flags = 0;
	return B_OK;
}


// #pragma mark - vnodes


static status_t
smbfs_lookup(fs_volume* fsVolume, fs_vnode* dir, const char* name, ino_t* _id)
{
	GET_VOLUME(fsVolume, dir, B_ENTRY_NOT_FOUND);
	Inode* directory = (Inode*)dir->private_node;

	status_t status = volume->Lookup(directory, name, _id);
	if (status != B_OK)
		return status;

	void* node;
	return get_vnode(fsVolume, *_id, &node);
}


static status_t
smbfs_get_vnode_name(fs_volume* fsVolume, fs_vnode* vnode, char* buffer,
	size_t bufferSize)
{
	GET_VOLUME(fsVolume, vnode, B_ENTRY_NOT_FOUND);
	Inode* inode = (Inode*)vnode->private_node;
	ReadLocker locker(volume->TreeLock());
	if (inode->IsRemoved() && inode != volume->Root())
		return B_ENTRY_NOT_FOUND;
	if (strlcpy(buffer, inode->Name(), bufferSize) >= bufferSize)
		return B_BUFFER_OVERFLOW;
	return B_OK;
}


static status_t
smbfs_put_vnode(fs_volume* fsVolume, fs_vnode* vnode, bool reenter)
{
	GET_VOLUME(fsVolume, vnode, B_OK);
	Inode* inode = (Inode*)vnode->private_node;
	if (inode == volume->Root())
		return B_OK;
	inode->DeleteFileCache();
	volume->InodeUnpublished(inode);
	return B_OK;
}


static status_t
smbfs_remove_vnode(fs_volume* fsVolume, fs_vnode* vnode, bool reenter)
{
	GET_VOLUME(fsVolume, vnode, B_OK);
	Inode* inode = (Inode*)vnode->private_node;
	if (inode == volume->Root())
		return B_OK;
	inode->DeleteFileCache();
	volume->RemoveInode(inode);
	return B_OK;
}


// #pragma mark - VM file access


static bool
smbfs_can_page(fs_volume* fsVolume, fs_vnode* vnode, void* cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return false;
	Inode* inode = (Inode*)vnode->private_node;
	return !inode->IsDirectory();
}


static status_t
smbfs_read_pages(fs_volume* fsVolume, fs_vnode* vnode, void* cookie,
	off_t pos, const iovec* vecs, size_t count, size_t* _numBytes)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	if (inode->IsDirectory())
		return B_IS_A_DIRECTORY;
	return inode->ReadPages((FileCookie*)cookie, pos, vecs, count, _numBytes);
}


static status_t
smbfs_write_pages(fs_volume* fsVolume, fs_vnode* vnode, void* cookie,
	off_t pos, const iovec* vecs, size_t count, size_t* _numBytes)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	if (inode->IsDirectory())
		return B_IS_A_DIRECTORY;
	return inode->WritePages((FileCookie*)cookie, pos, vecs, count,
		_numBytes);
}


// #pragma mark - common operations


static status_t
smbfs_ioctl(fs_volume* fsVolume, fs_vnode* vnode, void* cookie, uint32 op,
	void* buffer, size_t length)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	return B_DEV_INVALID_IOCTL;
}


static status_t
smbfs_set_flags(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie,
	int flags)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	FileCookie* cookie = (FileCookie*)_cookie;
	if (cookie != NULL)
		cookie->openMode = (cookie->openMode & ~O_APPEND) | (flags & O_APPEND);
	return B_OK;
}


static status_t
smbfs_fsync(fs_volume* fsVolume, fs_vnode* vnode, bool dataOnly)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->Sync(NULL);
}


static status_t
smbfs_unlink(fs_volume* fsVolume, fs_vnode* dir, const char* name)
{
	GET_VOLUME(fsVolume, dir, B_ENTRY_NOT_FOUND);
	Inode* directory = (Inode*)dir->private_node;
	TRACE("unlink(%s)\n", name);

	if (volume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return B_NOT_ALLOWED;

	// Find the entry first so that we know its inode number for the
	// notification (and get a proper error if it does not exist).
	ino_t id;
	status_t status = volume->Lookup(directory, name, &id);
	if (status != B_OK)
		return status;
	Inode* child = volume->GetInode(id);
	if (child != NULL && child->IsDirectory())
		return B_IS_A_DIRECTORY;

	char path[B_PATH_NAME_LENGTH];
	status = volume->BuildChildPath(directory, name, path, sizeof(path));
	if (status == B_OK)
		status = volume->GetConnection()->DeletePath(path, false);
	if (status != B_OK)
		return status;

	if (child != NULL)
		volume->DetachInode(child);
	notify_entry_removed(volume->ID(), directory->ID(), name, id);
	return B_OK;
}


static status_t
smbfs_rename(fs_volume* fsVolume, fs_vnode* fromDir, const char* fromName,
	fs_vnode* toDir, const char* toName)
{
	GET_VOLUME(fsVolume, fromDir, B_ENTRY_NOT_FOUND);
	Inode* fromDirectory = (Inode*)fromDir->private_node;
	Inode* toDirectory = (Inode*)toDir->private_node;
	TRACE("rename(%s -> %s)\n", fromName, toName);

	if (volume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (strcmp(fromName, ".") == 0 || strcmp(fromName, "..") == 0
		|| strcmp(toName, ".") == 0 || strcmp(toName, "..") == 0) {
		return B_NOT_ALLOWED;
	}

	ino_t id;
	status_t status = volume->Lookup(fromDirectory, fromName, &id);
	if (status != B_OK)
		return status;

	// Moving a directory into itself is not allowed.
	if (toDirectory->ID() == id)
		return B_BAD_VALUE;

	char fromPath[B_PATH_NAME_LENGTH];
	char toPath[B_PATH_NAME_LENGTH];
	status = volume->BuildChildPath(fromDirectory, fromName, fromPath,
		sizeof(fromPath));
	if (status == B_OK) {
		status = volume->BuildChildPath(toDirectory, toName, toPath,
			sizeof(toPath));
	}
	if (status != B_OK)
		return status;

	if (strcmp(fromPath, toPath) == 0)
		return B_OK;

	// Does the target already exist (and is it known to us)?
	ino_t targetID = 0;
	Inode* target = NULL;
	{
		ReadLocker locker(volume->TreeLock());
		target = toDirectory->FindChild(toName);
		if (target != NULL)
			targetID = target->ID();
	}

	status = volume->GetConnection()->RenamePath(fromPath, toPath, true);
	if (status != B_OK)
		return status;

	Inode* child = NULL;
	{
		WriteLocker locker(volume->TreeLock());
		child = fromDirectory->FindChild(fromName);
		target = toDirectory->FindChild(toName);
		if (target != NULL && target == child)
			target = NULL;
		if (child != NULL) {
			fromDirectory->RemoveChild(child);
			if (target != NULL) {
				toDirectory->RemoveChild(target);
				target->SetParent(NULL);
				target->MarkRemoved();
			}
			child->SetName(toName);
			child->SetParent(toDirectory);
			toDirectory->AddChild(child);
		}
	}
	if (child != NULL)
		child->InvalidateInfo();
	if (target != NULL)
		volume->DetachInode(target);

	if (targetID != 0 && targetID != id) {
		notify_entry_removed(volume->ID(), toDirectory->ID(), toName,
			targetID);
	}
	notify_entry_moved(volume->ID(), fromDirectory->ID(), fromName,
		toDirectory->ID(), toName, id);
	return B_OK;
}


static status_t
smbfs_access(fs_volume* fsVolume, fs_vnode* vnode, int mode)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->Access(mode);
}


static status_t
smbfs_read_stat(fs_volume* fsVolume, fs_vnode* vnode, struct stat* stat)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->ReadStat(stat);
}


static status_t
smbfs_write_stat(fs_volume* fsVolume, fs_vnode* vnode,
	const struct stat* stat, uint32 mask)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->WriteStat(stat, mask);
}


// #pragma mark - files


static status_t
smbfs_create(fs_volume* fsVolume, fs_vnode* dir, const char* name,
	int openMode, int perms, void** _cookie, ino_t* _newVnodeID)
{
	GET_VOLUME(fsVolume, dir, B_ENTRY_NOT_FOUND);
	Inode* directory = (Inode*)dir->private_node;
	TRACE("create(%s, mode %#x)\n", name, openMode);

	if (volume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (!directory->IsDirectory())
		return B_NOT_A_DIRECTORY;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return B_FILE_EXISTS;

	char path[B_PATH_NAME_LENGTH];
	status_t status = volume->BuildChildPath(directory, name, path,
		sizeof(path));
	if (status != B_OK)
		return status;

	FileCookie* cookie = new(std::nothrow) FileCookie;
	if (cookie == NULL)
		return B_NO_MEMORY;
	cookie->openMode = openMode;
	cookie->createOptions = FILE_NON_DIRECTORY_FILE;

	int accessMode = openMode & O_ACCMODE;
	uint32 access = FILE_READ_ATTRIBUTES;
	if (accessMode == O_RDONLY || accessMode == O_RDWR)
		access |= FILE_READ_DATA;
	if (accessMode == O_WRONLY || accessMode == O_RDWR)
		access |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES;
	cookie->desiredAccess = access;

	uint32 disposition;
	if ((openMode & O_EXCL) != 0)
		disposition = FILE_CREATE;
	else if ((openMode & O_TRUNC) != 0)
		disposition = FILE_OVERWRITE_IF;
	else
		disposition = FILE_OPEN_IF;

	Connection* connection = volume->GetConnection();
	FileInfo info;
	uint32 action = 0;
	status = connection->Create(path, access, FILE_SHARE_ALL, disposition,
		FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_NORMAL, cookie->id, &info,
		&action);
	if (status != B_OK) {
		delete cookie;
		return status;
	}
	cookie->generation = connection->Generation();

	Inode* child = volume->FindOrCreateChild(directory, name, &info);
	if (child == NULL) {
		connection->Close(cookie->id);
		delete cookie;
		return B_NO_MEMORY;
	}

	void* node;
	status = get_vnode(fsVolume, child->ID(), &node);
	if (status != B_OK) {
		connection->Close(cookie->id);
		delete cookie;
		return status;
	}

	child->AttachCookie(cookie);
	*_newVnodeID = child->ID();
	*_cookie = cookie;

	if (action == FILE_CREATED) {
		notify_entry_created(volume->ID(), directory->ID(), name,
			child->ID());
	} else if (action == FILE_OVERWRITTEN || action == FILE_SUPERSEDED) {
		notify_stat_changed(volume->ID(), directory->ID(), child->ID(),
			B_STAT_SIZE | B_STAT_MODIFICATION_TIME);
	}
	return B_OK;
}


static status_t
smbfs_open(fs_volume* fsVolume, fs_vnode* vnode, int openMode, void** _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	TRACE("open(%lld, mode %#x)\n", (long long)inode->ID(), openMode);
	FileCookie* cookie;
	status_t status = inode->Open(openMode, &cookie);
	if (status != B_OK)
		return status;
	*_cookie = cookie;
	return B_OK;
}


static status_t
smbfs_close(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	FileCookie* cookie = (FileCookie*)_cookie;
	if (cookie == NULL)
		return B_OK;
	return inode->Close(cookie);
}


static status_t
smbfs_free_cookie(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	FileCookie* cookie = (FileCookie*)_cookie;
	if (cookie == NULL)
		return B_OK;
	if (cookie->id.IsValid())
		inode->Close(cookie);
	delete cookie;
	return B_OK;
}


static status_t
smbfs_read(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie, off_t pos,
	void* buffer, size_t* _length)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	FileCookie* cookie = (FileCookie*)_cookie;
	if (cookie == NULL)
		return B_BAD_VALUE;
	if ((cookie->openMode & O_ACCMODE) == O_WRONLY)
		return B_NOT_ALLOWED;
	return inode->Read(cookie, pos, buffer, _length);
}


static status_t
smbfs_write(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie, off_t pos,
	const void* buffer, size_t* _length)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	FileCookie* cookie = (FileCookie*)_cookie;
	if (cookie == NULL)
		return B_BAD_VALUE;
	if ((cookie->openMode & O_ACCMODE) == O_RDONLY)
		return B_NOT_ALLOWED;
	return inode->Write(cookie, pos, buffer, _length);
}


// #pragma mark - directories


static status_t
smbfs_create_dir(fs_volume* fsVolume, fs_vnode* dir, const char* name,
	int perms)
{
	GET_VOLUME(fsVolume, dir, B_ENTRY_NOT_FOUND);
	Inode* directory = (Inode*)dir->private_node;
	TRACE("create_dir(%s)\n", name);

	if (volume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (!directory->IsDirectory())
		return B_NOT_A_DIRECTORY;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return B_FILE_EXISTS;

	char path[B_PATH_NAME_LENGTH];
	status_t status = volume->BuildChildPath(directory, name, path,
		sizeof(path));
	if (status != B_OK)
		return status;

	FileInfo info;
	status = volume->GetConnection()->CreateDirectoryPath(path, &info);
	if (status != B_OK)
		return status;

	Inode* child = volume->FindOrCreateChild(directory, name, &info);
	if (child == NULL)
		return B_NO_MEMORY;

	notify_entry_created(volume->ID(), directory->ID(), name, child->ID());
	return B_OK;
}


static status_t
smbfs_remove_dir(fs_volume* fsVolume, fs_vnode* dir, const char* name)
{
	GET_VOLUME(fsVolume, dir, B_ENTRY_NOT_FOUND);
	Inode* directory = (Inode*)dir->private_node;
	TRACE("remove_dir(%s)\n", name);

	if (volume->IsReadOnly())
		return B_READ_ONLY_DEVICE;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return B_NOT_ALLOWED;

	ino_t id;
	status_t status = volume->Lookup(directory, name, &id);
	if (status != B_OK)
		return status;
	Inode* child = volume->GetInode(id);
	if (child != NULL && !child->IsDirectory())
		return B_NOT_A_DIRECTORY;

	char path[B_PATH_NAME_LENGTH];
	status = volume->BuildChildPath(directory, name, path, sizeof(path));
	if (status == B_OK)
		status = volume->GetConnection()->DeletePath(path, true);
	if (status != B_OK)
		return status;

	if (child != NULL)
		volume->DetachInode(child);
	notify_entry_removed(volume->ID(), directory->ID(), name, id);
	return B_OK;
}


static status_t
smbfs_open_dir(fs_volume* fsVolume, fs_vnode* vnode, void** _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	DirCookie* cookie;
	status_t status = inode->OpenDir(&cookie);
	if (status != B_OK)
		return status;
	*_cookie = cookie;
	return B_OK;
}


static status_t
smbfs_close_dir(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->CloseDir((DirCookie*)_cookie);
}


static status_t
smbfs_free_dir_cookie(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	DirCookie* cookie = (DirCookie*)_cookie;
	if (cookie == NULL)
		return B_OK;
	if (cookie->id.IsValid())
		inode->CloseDir(cookie);
	free(cookie->buffer);
	delete cookie;
	return B_OK;
}


static status_t
smbfs_read_dir(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie,
	struct dirent* buffer, size_t bufferSize, uint32* _num)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->ReadDir((DirCookie*)_cookie, buffer, bufferSize, _num);
}


static status_t
smbfs_rewind_dir(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_OK;
	Inode* inode = (Inode*)vnode->private_node;
	return inode->RewindDir((DirCookie*)_cookie);
}


// #pragma mark - attributes


// Files get a single, read-only, virtual "BEOS:TYPE" attribute derived from
// their extension, so that Tracker and the registrar know the file type
// without sniffing file contents over the network (and without trying to
// write attributes, which the share cannot store).

static const char* kMimeTypeAttribute = "BEOS:TYPE";


struct AttrDirCookie {
	int32				index;
};


struct AttrCookie {
	const char*			type;
};


static const char*
mime_type_for_inode(Volume* volume, Inode* inode)
{
	if (inode->IsDirectory())
		return NULL;
	ReadLocker locker(volume->TreeLock());
	return mime_type_for_file_name(inode->Name());
}


static status_t
smbfs_open_attr_dir(fs_volume* fsVolume, fs_vnode* vnode, void** _cookie)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	AttrDirCookie* cookie = new(std::nothrow) AttrDirCookie;
	if (cookie == NULL)
		return B_NO_MEMORY;
	cookie->index = 0;
	*_cookie = cookie;
	return B_OK;
}


static status_t
smbfs_close_attr_dir(fs_volume* fsVolume, fs_vnode* vnode, void* cookie)
{
	return B_OK;
}


static status_t
smbfs_free_attr_dir_cookie(fs_volume* fsVolume, fs_vnode* vnode,
	void* _cookie)
{
	delete (AttrDirCookie*)_cookie;
	return B_OK;
}


static status_t
smbfs_rewind_attr_dir(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	((AttrDirCookie*)_cookie)->index = 0;
	return B_OK;
}


static status_t
smbfs_read_attr_dir(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie,
	struct dirent* buffer, size_t bufferSize, uint32* _num)
{
	GET_VOLUME(fsVolume, vnode, B_ENTRY_NOT_FOUND);
	Inode* inode = (Inode*)vnode->private_node;
	AttrDirCookie* cookie = (AttrDirCookie*)_cookie;

	if (cookie->index > 0 || *_num == 0
		|| mime_type_for_inode(volume, inode) == NULL) {
		*_num = 0;
		return B_OK;
	}

	size_t nameSize = strlen(kMimeTypeAttribute) + 1;
	size_t recordLength = offsetof(struct dirent, d_name) + nameSize;
	if (recordLength > bufferSize)
		return B_BUFFER_OVERFLOW;

	buffer->d_dev = volume->ID();
	buffer->d_pdev = 0;
	buffer->d_ino = inode->ID();
	buffer->d_pino = 0;
	buffer->d_reclen = (unsigned short)recordLength;
	memcpy(buffer->d_name, kMimeTypeAttribute, nameSize);
	cookie->index = 1;
	*_num = 1;
	return B_OK;
}


static status_t
smbfs_open_attr(fs_volume* fsVolume, fs_vnode* vnode, const char* name,
	int openMode, void** _cookie)
{
	GET_VOLUME(fsVolume, vnode, B_ENTRY_NOT_FOUND);
	Inode* inode = (Inode*)vnode->private_node;

	if (strcmp(name, kMimeTypeAttribute) != 0)
		return B_ENTRY_NOT_FOUND;
	const char* type = mime_type_for_inode(volume, inode);
	if (type == NULL)
		return B_ENTRY_NOT_FOUND;
	if ((openMode & O_ACCMODE) != O_RDONLY || (openMode & O_TRUNC) != 0)
		return B_READ_ONLY_DEVICE;

	AttrCookie* cookie = new(std::nothrow) AttrCookie;
	if (cookie == NULL)
		return B_NO_MEMORY;
	cookie->type = type;
	*_cookie = cookie;
	return B_OK;
}


static status_t
smbfs_close_attr(fs_volume* fsVolume, fs_vnode* vnode, void* cookie)
{
	return B_OK;
}


static status_t
smbfs_free_attr_cookie(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie)
{
	delete (AttrCookie*)_cookie;
	return B_OK;
}


static status_t
smbfs_read_attr(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie,
	off_t pos, void* buffer, size_t* _length)
{
	if (live_volume(fsVolume, vnode->private_node) == NULL)
		return B_ENTRY_NOT_FOUND;
	AttrCookie* cookie = (AttrCookie*)_cookie;
	size_t size = strlen(cookie->type) + 1;
	if (pos < 0)
		return B_BAD_VALUE;
	if ((size_t)pos >= size) {
		*_length = 0;
		return B_OK;
	}
	size_t length = *_length;
	if (length > size - pos)
		length = size - pos;
	if (IS_USER_ADDRESS(buffer)) {
		if (user_memcpy(buffer, cookie->type + pos, length) != B_OK)
			return B_BAD_ADDRESS;
	} else
		memcpy(buffer, cookie->type + pos, length);
	*_length = length;
	return B_OK;
}


static status_t
smbfs_read_attr_stat(fs_volume* fsVolume, fs_vnode* vnode, void* _cookie,
	struct stat* stat)
{
	GET_VOLUME(fsVolume, vnode, B_ENTRY_NOT_FOUND);
	Inode* inode = (Inode*)vnode->private_node;
	AttrCookie* cookie = (AttrCookie*)_cookie;

	memset(stat, 0, sizeof(*stat));
	stat->st_dev = volume->ID();
	stat->st_ino = inode->ID();
	stat->st_mode = S_ATTR | 0444;
	stat->st_nlink = 1;
	stat->st_uid = volume->Options().uid;
	stat->st_gid = volume->Options().gid;
	stat->st_size = strlen(cookie->type) + 1;
	stat->st_blksize = 65536;
	stat->st_type = B_MIME_STRING_TYPE;
	return B_OK;
}


// #pragma mark - tables


fs_volume_ops gSmbfsVolumeOps = {
	&smbfs_unmount,
	&smbfs_read_fs_info,
	NULL,	// write_fs_info
	&smbfs_sync,
	&smbfs_get_vnode,

	/* index directory & index operations */
	NULL,	// open_index_dir
	NULL,	// close_index_dir
	NULL,	// free_index_dir_cookie
	NULL,	// read_index_dir
	NULL,	// rewind_index_dir
	NULL,	// create_index
	NULL,	// remove_index
	NULL,	// read_index_stat

	/* query operations */
	NULL,	// open_query
	NULL,	// close_query
	NULL,	// free_query_cookie
	NULL,	// read_query
	NULL,	// rewind_query

	/* FS layer support */
	NULL,	// all_layers_mounted
	NULL,	// create_sub_vnode
	NULL,	// delete_sub_vnode
};


fs_vnode_ops gSmbfsVnodeOps = {
	/* vnode operations */
	&smbfs_lookup,
	&smbfs_get_vnode_name,
	&smbfs_put_vnode,
	&smbfs_remove_vnode,

	/* VM file access */
	&smbfs_can_page,
	&smbfs_read_pages,
	&smbfs_write_pages,

	/* asynchronous I/O */
	NULL,	// io
	NULL,	// cancel_io

	/* cache file access */
	NULL,	// get_file_map

	/* common operations */
	&smbfs_ioctl,
	&smbfs_set_flags,
	NULL,	// select
	NULL,	// deselect
	&smbfs_fsync,

	NULL,	// read_symlink
	NULL,	// create_symlink

	NULL,	// link
	&smbfs_unlink,
	&smbfs_rename,

	&smbfs_access,
	&smbfs_read_stat,
	&smbfs_write_stat,
	NULL,	// preallocate

	/* file operations */
	&smbfs_create,
	&smbfs_open,
	&smbfs_close,
	&smbfs_free_cookie,
	&smbfs_read,
	&smbfs_write,

	/* directory operations */
	&smbfs_create_dir,
	&smbfs_remove_dir,
	&smbfs_open_dir,
	&smbfs_close_dir,
	&smbfs_free_dir_cookie,
	&smbfs_read_dir,
	&smbfs_rewind_dir,

	/* attribute directory operations */
	&smbfs_open_attr_dir,
	&smbfs_close_attr_dir,
	&smbfs_free_attr_dir_cookie,
	&smbfs_read_attr_dir,
	&smbfs_rewind_attr_dir,

	/* attribute operations */
	NULL,	// create_attr
	&smbfs_open_attr,
	&smbfs_close_attr,
	&smbfs_free_attr_cookie,
	&smbfs_read_attr,
	NULL,	// write_attr
	&smbfs_read_attr_stat,
	NULL,	// write_attr_stat
	NULL,	// rename_attr
	NULL,	// remove_attr

	/* node and FS layer support */
	NULL,	// create_special_node
	NULL,	// get_super_vnode

	/* lock operations */
	NULL,	// test_lock
	NULL,	// acquire_lock
	NULL,	// release_lock
};


static file_system_module_info sSmbfsModuleInfo = {
	{
		"file_systems/smbfs" B_CURRENT_FS_API_VERSION,
		B_KEEP_LOADED,
		std_ops,
	},

	"smbfs",						// short_name
	"SMB2/3 network file system",	// pretty_name

	// DDM flags
	0,

	// scanning
	NULL,	// identify_partition
	NULL,	// scan_partition
	NULL,	// free_identify_partition_cookie
	NULL,	// free_partition_content_cookie

	&smbfs_mount,

	// capability querying
	NULL,	// get_supported_operations
	NULL,	// validate_resize
	NULL,	// validate_move
	NULL,	// validate_set_content_name
	NULL,	// validate_set_content_parameters
	NULL,	// validate_initialize

	NULL,	// shadow_changed

	NULL,	// defragment
	NULL,	// repair
	NULL,	// resize
	NULL,	// move
	NULL,	// set_content_name
	NULL,	// set_content_parameters
	NULL,	// initialize
	NULL,	// uninitialize
};


module_info* modules[] = {
	(module_info*)&sSmbfsModuleInfo,
	NULL,
};
