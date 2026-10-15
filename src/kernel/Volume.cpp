/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Volume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fs_volume.h>
#include <KernelExport.h>

#include "Inode.h"
#include "../smb2/Utf.h"

using namespace smb2;


static const size_t kInodeTableSize = 1024;
static const char* kFileSystemName = "smbfs";


Volume::Volume(fs_volume* fsVolume)
	:
	fFSVolume(fsVolume),
	fConnection(NULL),
	fRoot(NULL),
	fTableLock("smbfs inode table"),
	fTable(NULL),
	fTableSize(0),
	fTableCount(0),
	fNextID(1),
	fTreeLock("smbfs tree"),
	fUnmounted(false),
	fNextZombie(NULL)
{
	memset(&fOptions, 0, sizeof(fOptions));
}


Volume::~Volume()
{
	_FreeAllInodes();
	free(fTable);
	delete fConnection;
	memset(fOptions.password, 0, sizeof(fOptions.password));
}


// #pragma mark - argument parsing


static bool
next_token(const char*& position, char* out, size_t outSize)
{
	while (*position == ' ' || *position == '\t' || *position == '\n'
		|| *position == ';' || *position == ',') {
		position++;
	}
	if (*position == '\0')
		return false;

	size_t length = 0;
	char quote = '\0';
	while (*position != '\0') {
		char c = *position;
		if (quote != '\0') {
			if (c == quote) {
				quote = '\0';
				position++;
				continue;
			}
		} else {
			if (c == ' ' || c == '\t' || c == '\n' || c == ';' || c == ',')
				break;
			if (c == '"' || c == '\'') {
				quote = c;
				position++;
				continue;
			}
		}
		if (c == '\\' && position[1] != '\0' && quote != '\'') {
			position++;
			c = *position;
		}
		if (length + 1 < outSize)
			out[length++] = c;
		position++;
	}
	out[length] = '\0';
	return true;
}


static uint16
parse_dialect(const char* value)
{
	if (strcmp(value, "2.0.2") == 0 || strcmp(value, "2.02") == 0)
		return SMB2_DIALECT_202;
	if (strcmp(value, "2.1") == 0)
		return SMB2_DIALECT_210;
	if (strcmp(value, "3.0") == 0 || strcmp(value, "3") == 0)
		return SMB2_DIALECT_300;
	if (strcmp(value, "3.0.2") == 0 || strcmp(value, "3.02") == 0)
		return SMB2_DIALECT_302;
	if (strcmp(value, "3.1.1") == 0 || strcmp(value, "3.11") == 0)
		return SMB2_DIALECT_311;
	return (uint16)strtoul(value, NULL, 0);
}


static void
set_server_and_share(MountOptions& options, const char* unc)
{
	// Accepts //server/share, \\server\share and server/share.
	const char* p = unc;
	while (*p == '/' || *p == '\\')
		p++;
	const char* separator = p;
	while (*separator != '\0' && *separator != '/' && *separator != '\\')
		separator++;
	size_t serverLength = separator - p;
	if (serverLength >= sizeof(options.server))
		serverLength = sizeof(options.server) - 1;
	memcpy(options.server, p, serverLength);
	options.server[serverLength] = '\0';

	while (*separator == '/' || *separator == '\\')
		separator++;
	strlcpy(options.share, separator, sizeof(options.share));
	size_t length = strlen(options.share);
	while (length > 0 && (options.share[length - 1] == '/'
			|| options.share[length - 1] == '\\')) {
		options.share[--length] = '\0';
	}
}


status_t
Volume::_ParseArguments(const char* args)
{
	MountOptions& options = fOptions;
	memset(&options, 0, sizeof(options));
	options.port = kDefaultPort;
	options.uid = CurrentUserID();
	options.gid = CurrentGroupID();
	options.fileMode = 0644;
	options.directoryMode = 0755;
	options.minDialect = SMB2_DIALECT_202;
	options.maxDialect = SMB2_DIALECT_311;
	options.cacheTimeout = 2 * 1000000LL;
	options.requestTimeout = 30 * 1000000LL;
	strlcpy(options.workstation, "HAIKU", sizeof(options.workstation));

	if (args == NULL)
		return B_BAD_VALUE;

	bool first = true;
	const char* position = args;
	char token[1024];
	while (next_token(position, token, sizeof(token))) {
		char* value = strchr(token, '=');
		if (value != NULL) {
			*value = '\0';
			value++;
		}
		const char* key = token;

		if (first && value == NULL
			&& (strchr(key, '/') != NULL || strchr(key, '\\') != NULL)) {
			set_server_and_share(options, key);
			first = false;
			continue;
		}
		first = false;

		if (strcmp(key, "server") == 0 || strcmp(key, "host") == 0) {
			if (value != NULL)
				strlcpy(options.server, value, sizeof(options.server));
		} else if (strcmp(key, "share") == 0) {
			if (value != NULL)
				strlcpy(options.share, value, sizeof(options.share));
		} else if (strcmp(key, "unc") == 0) {
			if (value != NULL)
				set_server_and_share(options, value);
		} else if (strcmp(key, "user") == 0 || strcmp(key, "username") == 0) {
			if (value != NULL)
				strlcpy(options.user, value, sizeof(options.user));
		} else if (strcmp(key, "password") == 0 || strcmp(key, "pass") == 0) {
			if (value != NULL)
				strlcpy(options.password, value, sizeof(options.password));
		} else if (strcmp(key, "domain") == 0
			|| strcmp(key, "workgroup") == 0) {
			if (value != NULL)
				strlcpy(options.domain, value, sizeof(options.domain));
		} else if (strcmp(key, "workstation") == 0) {
			if (value != NULL) {
				strlcpy(options.workstation, value,
					sizeof(options.workstation));
			}
		} else if (strcmp(key, "port") == 0) {
			if (value != NULL)
				options.port = (uint16)strtoul(value, NULL, 0);
		} else if (strcmp(key, "uid") == 0) {
			if (value != NULL)
				options.uid = (uid_t)strtoul(value, NULL, 0);
		} else if (strcmp(key, "gid") == 0) {
			if (value != NULL)
				options.gid = (gid_t)strtoul(value, NULL, 0);
		} else if (strcmp(key, "fmask") == 0) {
			if (value != NULL)
				options.fileMode = 0777 & ~(mode_t)strtoul(value, NULL, 8);
		} else if (strcmp(key, "dmask") == 0) {
			if (value != NULL) {
				options.directoryMode
					= 0777 & ~(mode_t)strtoul(value, NULL, 8);
			}
		} else if (strcmp(key, "file_mode") == 0) {
			if (value != NULL)
				options.fileMode = 0777 & (mode_t)strtoul(value, NULL, 8);
		} else if (strcmp(key, "dir_mode") == 0) {
			if (value != NULL)
				options.directoryMode = 0777 & (mode_t)strtoul(value, NULL, 8);
		} else if (strcmp(key, "exec") == 0) {
			options.fileMode |= 0111;
		} else if (strcmp(key, "noexec") == 0) {
			options.fileMode &= ~(mode_t)0111;
		} else if (strcmp(key, "sign") == 0) {
			options.sign = value == NULL || strcmp(value, "true") == 0
				|| strcmp(value, "1") == 0 || strcmp(value, "yes") == 0;
		} else if (strcmp(key, "seal") == 0 || strcmp(key, "encrypt") == 0) {
			options.seal = value == NULL || strcmp(value, "true") == 0
				|| strcmp(value, "1") == 0 || strcmp(value, "yes") == 0;
		} else if (strcmp(key, "ro") == 0 || strcmp(key, "readonly") == 0) {
			options.readOnly = true;
		} else if (strcmp(key, "rw") == 0) {
			options.readOnly = false;
		} else if (strcmp(key, "trace") == 0 || strcmp(key, "debug") == 0) {
			options.trace = true;
		} else if (strcmp(key, "dialect") == 0 || strcmp(key, "maxdialect") == 0
			|| strcmp(key, "vers") == 0) {
			if (value != NULL)
				options.maxDialect = parse_dialect(value);
		} else if (strcmp(key, "mindialect") == 0) {
			if (value != NULL)
				options.minDialect = parse_dialect(value);
		} else if (strcmp(key, "cache") == 0 || strcmp(key, "actimeo") == 0) {
			if (value != NULL) {
				options.cacheTimeout
					= (bigtime_t)strtoul(value, NULL, 0) * 1000000LL;
			}
		} else if (strcmp(key, "timeout") == 0) {
			if (value != NULL) {
				options.requestTimeout
					= (bigtime_t)strtoul(value, NULL, 0) * 1000000LL;
				if (options.requestTimeout < 1000000LL)
					options.requestTimeout = 1000000LL;
			}
		} else {
			dprintf("smbfs: unknown mount option \"%s\"\n", key);
		}
	}

	if (options.server[0] == '\0' || options.share[0] == '\0') {
		dprintf("smbfs: server and share must be specified "
			"(e.g. \"//server/share user=name password=secret\")\n");
		return B_BAD_VALUE;
	}
	if (options.maxDialect < options.minDialect)
		return B_BAD_VALUE;
	return B_OK;
}


// #pragma mark - mounting


status_t
Volume::Mount(const char* args, uint32 flags)
{
	status_t status = _ParseArguments(args);
	if (status != B_OK)
		return status;
	if ((flags & B_MOUNT_READ_ONLY) != 0)
		fOptions.readOnly = true;
	SetTraceEnabled(fOptions.trace);

	fTable = (Inode**)calloc(kInodeTableSize, sizeof(Inode*));
	if (fTable == NULL)
		return B_NO_MEMORY;
	fTableSize = kInodeTableSize;

	fConnection = new(std::nothrow) Connection;
	if (fConnection == NULL)
		return B_NO_MEMORY;

	Credentials credentials;
	credentials.user = fOptions.user;
	credentials.password = fOptions.password;
	credentials.domain = fOptions.domain;
	credentials.workstation = fOptions.workstation;

	smb2::Options connectionOptions;
	connectionOptions.sign = fOptions.sign;
	connectionOptions.seal = fOptions.seal;
	connectionOptions.minDialect = fOptions.minDialect;
	connectionOptions.maxDialect = fOptions.maxDialect;
	connectionOptions.timeout = fOptions.requestTimeout;

	status = fConnection->Init(fOptions.server, fOptions.port, fOptions.share,
		credentials, connectionOptions);
	if (status != B_OK)
		return status;
	status = fConnection->Connect();
	if (status != B_OK) {
		dprintf("smbfs: connecting to //%s/%s failed: %s\n", fOptions.server,
			fOptions.share, strerror(status));
		return status;
	}

	if ((fConnection->MaximalAccess() & FILE_WRITE_DATA) == 0) {
		dprintf("smbfs: share //%s/%s is read-only for this user\n",
			fOptions.server, fOptions.share);
		fOptions.readOnly = true;
	}

	fRoot = new(std::nothrow) Inode(this, _NextID(), NULL, "", true);
	if (fRoot == NULL || fRoot->InitCheck() != B_OK) {
		delete fRoot;
		fRoot = NULL;
		return B_NO_MEMORY;
	}

	FileInfo info;
	status = fConnection->QueryPathInfo("", info);
	if (status != B_OK) {
		dprintf("smbfs: cannot access the root of //%s/%s: %s\n",
			fOptions.server, fOptions.share, strerror(status));
		delete fRoot;
		fRoot = NULL;
		return status;
	}
	fRoot->UpdateInfo(info);
	_TableInsert(fRoot);
	return B_OK;
}


// Called from the unmount hook. Everything but this object and the root
// inode is released here; the VFS may still call vnode hooks on the root
// vnode until it frees it (see smbfs_put_vnode()), so the root stays alive
// and all hooks check IsUnmounted().
status_t
Volume::Unmount()
{
	fUnmounted = true;

	if (fConnection != NULL) {
		fConnection->Disconnect();
		delete fConnection;
		fConnection = NULL;
	}

	MutexLocker locker(fTableLock);
	for (size_t i = 0; i < fTableSize; i++) {
		Inode* inode = fTable[i];
		while (inode != NULL) {
			Inode* next = inode->fNextInTable;
			if (inode != fRoot)
				delete inode;
			inode = next;
		}
		fTable[i] = NULL;
	}
	fTableCount = 0;
	if (fRoot != NULL) {
		fRoot->fFirstChild = NULL;
		fRoot->fNextInTable = NULL;
		fTable[(size_t)fRoot->ID() % fTableSize] = fRoot;
		fTableCount = 1;
	}
	return B_OK;
}


// #pragma mark - inode table


ino_t
Volume::_NextID()
{
	MutexLocker locker(fTableLock);
	return fNextID++;
}


void
Volume::_TableInsert(Inode* inode)
{
	MutexLocker locker(fTableLock);
	size_t index = (size_t)inode->ID() % fTableSize;
	inode->fNextInTable = fTable[index];
	fTable[index] = inode;
	fTableCount++;
}


void
Volume::_TableRemove(Inode* inode)
{
	// fTableLock must be held
	size_t index = (size_t)inode->ID() % fTableSize;
	Inode** link = &fTable[index];
	while (*link != NULL) {
		if (*link == inode) {
			*link = inode->fNextInTable;
			inode->fNextInTable = NULL;
			fTableCount--;
			return;
		}
		link = &(*link)->fNextInTable;
	}
}


void
Volume::_FreeAllInodes()
{
	if (fTable == NULL)
		return;
	for (size_t i = 0; i < fTableSize; i++) {
		Inode* inode = fTable[i];
		while (inode != NULL) {
			Inode* next = inode->fNextInTable;
			delete inode;
			inode = next;
		}
		fTable[i] = NULL;
	}
	fTableCount = 0;
	fRoot = NULL;
}


Inode*
Volume::GetInode(ino_t id)
{
	if (fUnmounted)
		return NULL;
	MutexLocker locker(fTableLock);
	Inode* inode = fTable[(size_t)id % fTableSize];
	while (inode != NULL && inode->ID() != id)
		inode = inode->fNextInTable;
	return inode;
}


// Used by the get_vnode() hook only: looks up the inode and marks it as
// having a vnode in the VFS. The flag is cleared by InodeUnpublished() from
// the put_vnode()/remove_vnode() hooks.
Inode*
Volume::AcquireForVnode(ino_t id)
{
	if (fUnmounted)
		return NULL;
	MutexLocker locker(fTableLock);
	Inode* inode = fTable[(size_t)id % fTableSize];
	while (inode != NULL && inode->ID() != id)
		inode = inode->fNextInTable;
	if (inode != NULL)
		inode->SetPublished(true);
	return inode;
}


void
Volume::InodeUnpublished(Inode* inode)
{
	bool dispose = false;
	{
		MutexLocker locker(fTableLock);
		inode->SetPublished(false);
		if (inode->IsRemoved()) {
			_TableRemove(inode);
			dispose = true;
		}
	}
	if (dispose)
		delete inode;
}


void
Volume::RemoveInode(Inode* inode)
{
	if (inode->Parent() != NULL) {
		WriteLocker locker(fTreeLock);
		if (inode->Parent() != NULL) {
			inode->Parent()->RemoveChild(inode);
			inode->SetParent(NULL);
		}
		inode->MarkRemoved();
	}
	{
		MutexLocker locker(fTableLock);
		inode->SetPublished(false);
		_TableRemove(inode);
	}
	delete inode;
}


// Detaches the inode (and its cached descendants) from the tree. Published
// inodes are handed to the VFS for removal; unpublished ones are freed.
void
Volume::DetachInode(Inode* inode)
{
	if (inode == fRoot)
		return;

	Inode* disposeList = NULL;
	{
		WriteLocker locker(fTreeLock);
		if (inode->Parent() != NULL) {
			inode->Parent()->RemoveChild(inode);
			inode->SetParent(NULL);
		}
		inode->MarkRemoved();

		// Collect the subtree into a flat list (reusing the sibling link).
		Inode* stack = inode;
		inode->fNextSibling = NULL;
		while (stack != NULL) {
			Inode* current = stack;
			stack = current->fNextSibling;
			current->fNextSibling = disposeList;
			disposeList = current;

			Inode* child = current->FirstChild();
			current->fFirstChild = NULL;
			while (child != NULL) {
				Inode* next = child->NextSibling();
				child->SetParent(NULL);
				child->MarkRemoved();
				child->fNextSibling = stack;
				stack = child;
				child = next;
			}
		}
	}

	while (disposeList != NULL) {
		Inode* current = disposeList;
		disposeList = current->fNextSibling;
		current->fNextSibling = NULL;

		bool published;
		{
			MutexLocker locker(fTableLock);
			published = current->IsPublished();
			if (!published)
				_TableRemove(current);
		}
		if (!published) {
			delete current;
			continue;
		}

		// Let the VFS remove the vnode; our remove_vnode hook frees it.
		ino_t id = current->ID();
		void* node;
		if (get_vnode(fFSVolume, id, &node) == B_OK) {
			remove_vnode(fFSVolume, id);
			put_vnode(fFSVolume, id);
		}
	}
}


Inode*
Volume::FindOrCreateChild(Inode* directory, const char* name,
	const FileInfo* info)
{
	bool isDirectory = info != NULL ? info->IsDirectory() : false;
	Inode* stale = NULL;
	Inode* child = NULL;
	{
		WriteLocker locker(fTreeLock);
		child = directory->FindChild(name);
		if (child != NULL && info != NULL
			&& child->IsDirectory() != isDirectory) {
			directory->RemoveChild(child);
			child->SetParent(NULL);
			child->MarkRemoved();
			stale = child;
			child = NULL;
		}
		if (child == NULL) {
			child = new(std::nothrow) Inode(this, _NextID(), directory, name,
				isDirectory);
			if (child == NULL || child->InitCheck() != B_OK) {
				delete child;
				child = NULL;
			} else {
				directory->AddChild(child);
				_TableInsert(child);
			}
		}
		if (child != NULL && info != NULL)
			child->UpdateInfo(*info);
	}

	if (stale != NULL) {
		bool published;
		{
			MutexLocker locker(fTableLock);
			published = stale->IsPublished();
			if (!published)
				_TableRemove(stale);
		}
		if (!published)
			delete stale;
		else {
			ino_t id = stale->ID();
			void* node;
			if (get_vnode(fFSVolume, id, &node) == B_OK) {
				remove_vnode(fFSVolume, id);
				put_vnode(fFSVolume, id);
			}
		}
	}
	return child;
}


status_t
Volume::Lookup(Inode* directory, const char* name, ino_t* _id)
{
	if (!directory->IsDirectory())
		return B_NOT_A_DIRECTORY;

	if (strcmp(name, ".") == 0) {
		*_id = directory->ID();
		return B_OK;
	}
	if (strcmp(name, "..") == 0) {
		ReadLocker locker(fTreeLock);
		Inode* parent = directory->Parent();
		*_id = parent != NULL ? parent->ID() : directory->ID();
		return B_OK;
	}

	{
		ReadLocker locker(fTreeLock);
		Inode* child = directory->FindChild(name);
		if (child != NULL && !child->IsRemoved() && child->InfoIsFresh()) {
			*_id = child->ID();
			return B_OK;
		}
	}

	char path[B_PATH_NAME_LENGTH];
	status_t status = BuildChildPath(directory, name, path, sizeof(path));
	if (status != B_OK)
		return status;

	FileInfo info;
	status = fConnection->QueryPathInfo(path, info);
	if (status != B_OK) {
		if (status == B_ENTRY_NOT_FOUND) {
			Inode* stale = NULL;
			{
				ReadLocker locker(fTreeLock);
				stale = directory->FindChild(name);
			}
			if (stale != NULL)
				DetachInode(stale);
		}
		return status;
	}

	Inode* child = FindOrCreateChild(directory, name, &info);
	if (child == NULL)
		return B_NO_MEMORY;
	*_id = child->ID();
	return B_OK;
}


// #pragma mark - paths


status_t
Volume::BuildPath(Inode* inode, char* buffer, size_t bufferSize)
{
	if (buffer == NULL || bufferSize == 0)
		return B_NO_MEMORY;

	ReadLocker locker(fTreeLock);

	if (inode->IsRemoved() && inode != fRoot)
		return B_ENTRY_NOT_FOUND;

	// Build the path backwards.
	size_t position = bufferSize - 1;
	buffer[position] = '\0';
	for (Inode* current = inode; current != NULL && current != fRoot;
			current = current->Parent()) {
		if (current->IsRemoved())
			return B_ENTRY_NOT_FOUND;
		const char* name = current->Name();
		size_t length = strlen(name);
		if (length + 1 > position)
			return B_NAME_TOO_LONG;
		position -= length;
		memcpy(buffer + position, name, length);
		if (current->Parent() != NULL && current->Parent() != fRoot)
			buffer[--position] = '/';
		if (current->Parent() == NULL)
			return B_ENTRY_NOT_FOUND;
	}
	memmove(buffer, buffer + position, bufferSize - position);
	return B_OK;
}


status_t
Volume::BuildChildPath(Inode* directory, const char* name, char* buffer,
	size_t bufferSize)
{
	status_t status = BuildPath(directory, buffer, bufferSize);
	if (status != B_OK)
		return status;
	size_t length = strlen(buffer);
	size_t nameLength = strlen(name);
	if (length + nameLength + 2 > bufferSize)
		return B_NAME_TOO_LONG;
	if (length > 0)
		buffer[length++] = '/';
	memcpy(buffer + length, name, nameLength + 1);
	return B_OK;
}


// #pragma mark - misc


mode_t
Volume::ModeFor(const FileInfo& info) const
{
	mode_t mode;
	if (info.IsDirectory())
		mode = S_IFDIR | fOptions.directoryMode;
	else
		mode = S_IFREG | fOptions.fileMode;
	if (info.IsReadOnly() || fOptions.readOnly)
		mode &= ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);
	return mode;
}


status_t
Volume::ReadFsInfo(struct fs_info* info)
{
	FsInfo fsInfo;
	status_t status = fConnection->QueryFsInfo(fsInfo);
	if (status != B_OK)
		return status;

	uint64 unit = (uint64)fsInfo.sectorsPerUnit * fsInfo.bytesPerSector;
	if (unit == 0)
		unit = 4096;

	info->flags = B_FS_IS_PERSISTENT | B_FS_IS_SHARED;
	if (fOptions.readOnly)
		info->flags |= B_FS_IS_READONLY;
	info->block_size = unit;
	info->io_size = 65536;
	info->total_blocks = fsInfo.totalUnits;
	info->free_blocks = fsInfo.availableUnits;
	info->total_nodes = 0;
	info->free_nodes = 0;
	strlcpy(info->volume_name, fOptions.share, sizeof(info->volume_name));
	strlcpy(info->fsh_name, kFileSystemName, sizeof(info->fsh_name));
	snprintf(info->device_name, sizeof(info->device_name), "//%s/%s",
		fOptions.server, fOptions.share);
	return B_OK;
}
