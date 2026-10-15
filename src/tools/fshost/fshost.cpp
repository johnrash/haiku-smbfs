/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Userland host for the smbfs kernel add-on: emulates the parts of Haiku's
 * VFS that the add-on relies on, and drives the add-on's hooks through a
 * scenario similar to real usage. Meant to be run under AddressSanitizer
 * against a real SMB server.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../kernel/Volume.h"
#include "../../smb2/Platform.h"

extern module_info* modules[];


// #pragma mark - fake VFS


struct Vnode {
	ino_t		id;
	fs_vnode	node;
	int			refCount;
	bool		removed;
	Vnode*		next;
};

static fs_volume gVolume;
static Vnode* gVnodes = NULL;
static ino_t gRootID = 0;
static int gVnodeCount = 0;
static int gNotifications = 0;
static int gFailures = 0;
static bool gVerbose = false;

#define CHECK(condition, ...) \
	do { \
		if (!(condition)) { \
			gFailures++; \
			printf("FAIL %s:%d: ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	} while (0)


static Vnode*
find_vnode(ino_t id)
{
	for (Vnode* vnode = gVnodes; vnode != NULL; vnode = vnode->next) {
		if (vnode->id == id)
			return vnode;
	}
	return NULL;
}


static void
free_vnode(Vnode* vnode)
{
	// mirrors vfs.cpp free_vnode()
	if (!vnode->removed && vnode->node.ops->fsync != NULL)
		vnode->node.ops->fsync(&gVolume, &vnode->node, false);
	if (vnode->removed)
		vnode->node.ops->remove_vnode(&gVolume, &vnode->node, false);
	else
		vnode->node.ops->put_vnode(&gVolume, &vnode->node, false);

	Vnode** link = &gVnodes;
	while (*link != vnode)
		link = &(*link)->next;
	*link = vnode->next;
	free(vnode);
	gVnodeCount--;
}


extern "C" status_t
publish_vnode(fs_volume* volume, ino_t vnodeID, void* privateNode,
	fs_vnode_ops* ops, int type, uint32 flags)
{
	Vnode* vnode = (Vnode*)calloc(1, sizeof(Vnode));
	vnode->id = vnodeID;
	vnode->node.private_node = privateNode;
	vnode->node.ops = ops;
	vnode->refCount = 1;
	vnode->next = gVnodes;
	gVnodes = vnode;
	gVnodeCount++;
	return B_OK;
}


extern "C" status_t
new_vnode(fs_volume* volume, ino_t vnodeID, void* privateNode,
	fs_vnode_ops* ops)
{
	return publish_vnode(volume, vnodeID, privateNode, ops, 0, 0);
}


extern "C" status_t
get_vnode(fs_volume* volume, ino_t vnodeID, void** _privateNode)
{
	Vnode* vnode = find_vnode(vnodeID);
	if (vnode == NULL) {
		// Like the real VFS: the (busy) vnode is in the table while the
		// file system's get_vnode() hook runs.
		vnode = (Vnode*)calloc(1, sizeof(Vnode));
		vnode->id = vnodeID;
		vnode->refCount = 0;
		vnode->next = gVnodes;
		gVnodes = vnode;
		gVnodeCount++;
		int type;
		uint32 flags;
		status_t status = volume->ops->get_vnode(volume, vnodeID,
			&vnode->node, &type, &flags, true);
		if (status != B_OK) {
			gVnodes = vnode->next;
			gVnodeCount--;
			free(vnode);
			return status;
		}
	}
	vnode->refCount++;
	if (_privateNode != NULL)
		*_privateNode = vnode->node.private_node;
	return B_OK;
}


extern "C" status_t
acquire_vnode(fs_volume* volume, ino_t vnodeID)
{
	Vnode* vnode = find_vnode(vnodeID);
	if (vnode == NULL)
		return B_ENTRY_NOT_FOUND;
	vnode->refCount++;
	return B_OK;
}


extern "C" status_t
put_vnode(fs_volume* volume, ino_t vnodeID)
{
	Vnode* vnode = find_vnode(vnodeID);
	if (vnode == NULL) {
		CHECK(false, "put_vnode(%lld): unknown vnode", (long long)vnodeID);
		return B_BAD_VALUE;
	}
	CHECK(vnode->refCount > 0, "put_vnode(%lld): no reference held",
		(long long)vnodeID);
	vnode->refCount--;
	// Unreferenced vnodes stay cached (the VFS keeps them in an unused
	// list) unless they were removed.
	if (vnode->refCount == 0 && vnode->removed)
		free_vnode(vnode);
	return B_OK;
}


extern "C" status_t
remove_vnode(fs_volume* volume, ino_t vnodeID)
{
	Vnode* vnode = find_vnode(vnodeID);
	if (vnode == NULL)
		return B_ENTRY_NOT_FOUND;
	vnode->removed = true;
	return B_OK;
}


extern "C" status_t
unremove_vnode(fs_volume* volume, ino_t vnodeID)
{
	Vnode* vnode = find_vnode(vnodeID);
	if (vnode == NULL)
		return B_ENTRY_NOT_FOUND;
	vnode->removed = false;
	return B_OK;
}


extern "C" status_t
notify_entry_created(dev_t device, ino_t directory, const char* name,
	ino_t node)
{
	gNotifications++;
	if (gVerbose)
		printf("  [notify] created %s (dir %lld, node %lld)\n", name,
			(long long)directory, (long long)node);
	return B_OK;
}


extern "C" status_t
notify_entry_removed(dev_t device, ino_t directory, const char* name,
	ino_t node)
{
	gNotifications++;
	if (gVerbose)
		printf("  [notify] removed %s (dir %lld, node %lld)\n", name,
			(long long)directory, (long long)node);
	return B_OK;
}


extern "C" status_t
notify_entry_moved(dev_t device, ino_t fromDirectory, const char* fromName,
	ino_t toDirectory, const char* toName, ino_t node)
{
	gNotifications++;
	if (gVerbose)
		printf("  [notify] moved %s -> %s (node %lld)\n", fromName, toName,
			(long long)node);
	return B_OK;
}


extern "C" status_t
notify_stat_changed(dev_t device, ino_t directory, ino_t node,
	uint32 statFields)
{
	gNotifications++;
	if (gVerbose)
		printf("  [notify] stat changed node %lld (0x%x)\n", (long long)node,
			statFields);
	return B_OK;
}


extern "C" void
dprintf(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	printf("  KERN: ");
	vprintf(format, args);
	va_end(args);
}


extern "C" status_t
user_memcpy(void* to, const void* from, size_t size)
{
	memcpy(to, from, size);
	return B_OK;
}


// Minimal file cache emulation: no caching, but the same size semantics as
// the kernel's cache (I/O is clipped to the cache size and goes through the
// read_pages()/write_pages() hooks).
struct FakeFileCache {
	ino_t	id;
	off_t	size;
	int		disabled;
	uint8*	dirty;			// data of the last write, "flushed" on sync
	off_t	dirtyOffset;
	size_t	dirtyLength;
};
static int gFileCaches = 0;
static int gCacheIODepth = 0;
// When set, file_cache_write() only keeps the data as dirty, and it reaches
// the file system later through write_pages() without a cookie, like the
// kernel's page writer does it. Otherwise writes go through immediately.
static bool gDeferWrites = false;

// The kernel's file cache is busy while it calls read_pages()/write_pages();
// the file system must not call back into it from there.
#define CHECK_NOT_IN_CACHE_IO(what) \
	CHECK(gCacheIODepth == 0, "%s called from within cache I/O", what)

extern "C" void*
file_cache_create(dev_t mountID, ino_t vnodeID, off_t size)
{
	CHECK_NOT_IN_CACHE_IO("file_cache_create");
	CHECK(find_vnode(vnodeID) != NULL, "file_cache_create for unknown vnode %lld", (long long)vnodeID);
	FakeFileCache* cache = (FakeFileCache*)calloc(1, sizeof(FakeFileCache));
	cache->id = vnodeID;
	cache->size = size;
	gFileCaches++;
	return cache;
}

extern "C" void
file_cache_delete(void* cacheRef)
{
	CHECK_NOT_IN_CACHE_IO("file_cache_delete");
	FakeFileCache* cache = (FakeFileCache*)cacheRef;
	free(cache->dirty);
	gFileCaches--;
	free(cache);
}

extern "C" void file_cache_enable(void* cacheRef) { CHECK_NOT_IN_CACHE_IO("file_cache_enable"); ((FakeFileCache*)cacheRef)->disabled--; }
extern "C" status_t file_cache_disable(void* cacheRef) { CHECK_NOT_IN_CACHE_IO("file_cache_disable"); ((FakeFileCache*)cacheRef)->disabled++; return B_OK; }
extern "C" status_t file_cache_set_size(void* cacheRef, off_t size) { CHECK_NOT_IN_CACHE_IO("file_cache_set_size"); ((FakeFileCache*)cacheRef)->size = size; return B_OK; }

static status_t
fake_cache_pages(FakeFileCache* cache, void* cookie, off_t offset, void* buffer, size_t* _size, bool write)
{
	Vnode* vnode = find_vnode(cache->id);
	CHECK(vnode != NULL, "cache I/O on unknown vnode");
	if (vnode == NULL) return B_ERROR;
	iovec vec; vec.iov_base = buffer; vec.iov_len = *_size;
	gCacheIODepth++;
	status_t status = write
		? vnode->node.ops->write_pages(&gVolume, &vnode->node, cookie, offset, &vec, 1, _size)
		: vnode->node.ops->read_pages(&gVolume, &vnode->node, cookie, offset, &vec, 1, _size);
	gCacheIODepth--;
	return status;
}

// Mimics the page writer flushing dirty pages with no cookie.
extern "C" status_t
file_cache_sync(void* cacheRef)
{
	CHECK_NOT_IN_CACHE_IO("file_cache_sync");
	FakeFileCache* cache = (FakeFileCache*)cacheRef;
	if (cache->dirty == NULL)
		return B_OK;
	size_t size = cache->dirtyLength;
	status_t status = fake_cache_pages(cache, NULL, cache->dirtyOffset, cache->dirty, &size, true);
	free(cache->dirty);
	cache->dirty = NULL;
	return status;
}

static status_t
fake_cache_io(void* cacheRef, void* cookie, off_t offset, void* buffer, size_t* _size, bool write)
{
	FakeFileCache* cache = (FakeFileCache*)cacheRef;
	if (offset >= cache->size) { *_size = 0; return B_OK; }
	size_t size = *_size;
	if ((off_t)(offset + size) > cache->size) size = (size_t)(cache->size - offset);
	if (write && gDeferWrites) {
		// keep the data only in the "cache"; file_cache_sync() writes it
		off_t start = cache->dirty != NULL && cache->dirtyOffset < offset
			? cache->dirtyOffset : offset;
		off_t end = offset + (off_t)size;
		if (cache->dirty != NULL
			&& cache->dirtyOffset + (off_t)cache->dirtyLength > end)
			end = cache->dirtyOffset + (off_t)cache->dirtyLength;
		uint8* merged = (uint8*)calloc(1, (size_t)(end - start));
		if (cache->dirty != NULL) {
			memcpy(merged + (cache->dirtyOffset - start), cache->dirty,
				cache->dirtyLength);
		}
		memcpy(merged + (offset - start), buffer, size);
		free(cache->dirty);
		cache->dirty = merged;
		cache->dirtyOffset = start;
		cache->dirtyLength = (size_t)(end - start);
		*_size = size;
		return B_OK;
	}
	if (write) {
		// remember the write as "dirty" and flush it later (like the page
		// writer would), but also write through to keep the test simple
		free(cache->dirty);
		cache->dirty = (uint8*)malloc(size);
		memcpy(cache->dirty, buffer, size);
		cache->dirtyOffset = offset;
		cache->dirtyLength = size;
	}
	status_t status = fake_cache_pages(cache, cookie, offset, buffer, &size, write);
	*_size = size;
	return status;
}

extern "C" status_t
file_cache_read(void* cacheRef, void* cookie, off_t offset, void* buffer, size_t* _size)
{
	return fake_cache_io(cacheRef, cookie, offset, buffer, _size, false);
}

extern "C" status_t
file_cache_write(void* cacheRef, void* cookie, off_t offset, const void* buffer, size_t* _size)
{
	return fake_cache_io(cacheRef, cookie, offset, (void*)buffer, _size, true);
}


// Simulates the VFS dropping cached, unreferenced vnodes (low memory).
static void
evict_unused_vnodes()
{
	Vnode* vnode = gVnodes;
	while (vnode != NULL) {
		Vnode* next = vnode->next;
		if (vnode->refCount == 0 && vnode->id != gRootID)
			free_vnode(vnode);
		vnode = next;
	}
}


// #pragma mark - path helpers (mimic VFS behaviour)


static fs_vnode_ops* gOps = NULL;
static const char* gServer = NULL;
static const char* gShare = NULL;
static const char* gUser = NULL;
static const char* gPassword = NULL;


// Looks up a path; returns the vnode with a reference held.
static status_t
lookup_path(const char* path, Vnode** _vnode)
{
	Vnode* current = find_vnode(gRootID);
	current->refCount++;

	char copy[1024];
	strlcpy(copy, path, sizeof(copy));
	char* save;
	for (char* component = strtok_r(copy, "/", &save); component != NULL;
			component = strtok_r(NULL, "/", &save)) {
		ino_t id;
		status_t status = gOps->lookup(&gVolume, &current->node, component,
			&id);
		put_vnode(&gVolume, current->id);
		if (status != B_OK)
			return status;
		current = find_vnode(id);
		CHECK(current != NULL, "lookup returned unknown vnode %lld",
			(long long)id);
		if (current == NULL)
			return B_ERROR;
	}
	*_vnode = current;
	return B_OK;
}


static status_t
split_path(const char* path, Vnode** _dir, char* name)
{
	const char* slash = strrchr(path, '/');
	char dirPath[1024];
	if (slash == NULL) {
		dirPath[0] = '\0';
		strlcpy(name, path, B_FILE_NAME_LENGTH);
	} else {
		size_t length = slash - path;
		memcpy(dirPath, path, length);
		dirPath[length] = '\0';
		strlcpy(name, slash + 1, B_FILE_NAME_LENGTH);
	}
	return lookup_path(dirPath, _dir);
}


static status_t
fs_stat(const char* path, struct stat* st)
{
	Vnode* vnode;
	status_t status = lookup_path(path, &vnode);
	if (status != B_OK)
		return status;
	status = gOps->read_stat(&gVolume, &vnode->node, st);
	put_vnode(&gVolume, vnode->id);
	return status;
}


static status_t
fs_write_file(const char* path, const void* data, size_t length, int mode)
{
	Vnode* dir;
	char name[B_FILE_NAME_LENGTH];
	status_t status = split_path(path, &dir, name);
	if (status != B_OK)
		return status;
	void* cookie;
	ino_t id;
	status = gOps->create(&gVolume, &dir->node, name, mode | O_CREAT, 0644,
		&cookie, &id);
	put_vnode(&gVolume, dir->id);
	if (status != B_OK)
		return status;
	Vnode* vnode = find_vnode(id);
	CHECK(vnode != NULL && vnode->refCount >= 1,
		"create did not leave a reference");
	size_t done = 0;
	while (done < length && status == B_OK) {
		size_t chunk = length - done;
		status = gOps->write(&gVolume, &vnode->node, cookie, done,
			(const uint8*)data + done, &chunk);
		if (chunk == 0)
			break;
		done += chunk;
	}
	gOps->close(&gVolume, &vnode->node, cookie);
	gOps->free_cookie(&gVolume, &vnode->node, cookie);
	put_vnode(&gVolume, id);
	if (status == B_OK && done != length)
		status = B_IO_ERROR;
	return status;
}


static status_t
fs_read_file(const char* path, uint8** _data, size_t* _length, bool pages)
{
	Vnode* vnode;
	status_t status = lookup_path(path, &vnode);
	if (status != B_OK)
		return status;
	void* cookie;
	status = gOps->open(&gVolume, &vnode->node, O_RDONLY, &cookie);
	if (status != B_OK) {
		put_vnode(&gVolume, vnode->id);
		return status;
	}
	struct stat st;
	gOps->read_stat(&gVolume, &vnode->node, &st);
	size_t size = (size_t)st.st_size;
	uint8* data = (uint8*)malloc(size + 1);
	size_t done = 0;
	while (done < size) {
		size_t chunk = size - done;
		if (pages) {
			iovec vec;
			vec.iov_base = data + done;
			vec.iov_len = chunk > 4096 ? 4096 : chunk;
			status = gOps->read_pages(&gVolume, &vnode->node, cookie, done,
				&vec, 1, &chunk);
		} else {
			status = gOps->read(&gVolume, &vnode->node, cookie, done,
				data + done, &chunk);
		}
		if (status != B_OK || chunk == 0)
			break;
		done += chunk;
	}
	gOps->close(&gVolume, &vnode->node, cookie);
	gOps->free_cookie(&gVolume, &vnode->node, cookie);
	put_vnode(&gVolume, vnode->id);
	*_data = data;
	*_length = done;
	return status;
}


static status_t
fs_list(const char* path, int* _count, bool print)
{
	Vnode* vnode;
	status_t status = lookup_path(path, &vnode);
	if (status != B_OK)
		return status;
	void* cookie;
	status = gOps->open_dir(&gVolume, &vnode->node, &cookie);
	if (status != B_OK) {
		put_vnode(&gVolume, vnode->id);
		return status;
	}
	int count = 0;
	char buffer[4096];
	for (int pass = 0; pass < 2; pass++) {
		count = 0;
		while (true) {
			uint32 num = 8;
			status = gOps->read_dir(&gVolume, &vnode->node, cookie,
				(struct dirent*)buffer, sizeof(buffer), &num);
			if (status != B_OK || num == 0)
				break;
			struct dirent* entry = (struct dirent*)buffer;
			for (uint32 i = 0; i < num; i++) {
				if (print)
					printf("    %lld %s\n", (long long)entry->d_ino,
						entry->d_name);
				count++;
				entry = (struct dirent*)((uint8*)entry + entry->d_reclen);
			}
		}
		if (pass == 0)
			gOps->rewind_dir(&gVolume, &vnode->node, cookie);
	}
	gOps->close_dir(&gVolume, &vnode->node, cookie);
	gOps->free_dir_cookie(&gVolume, &vnode->node, cookie);
	put_vnode(&gVolume, vnode->id);
	*_count = count;
	return status;
}


static status_t
fs_unlink(const char* path)
{
	Vnode* dir;
	char name[B_FILE_NAME_LENGTH];
	status_t status = split_path(path, &dir, name);
	if (status != B_OK)
		return status;
	status = gOps->unlink(&gVolume, &dir->node, name);
	put_vnode(&gVolume, dir->id);
	return status;
}


static status_t
fs_rmdir(const char* path)
{
	Vnode* dir;
	char name[B_FILE_NAME_LENGTH];
	status_t status = split_path(path, &dir, name);
	if (status != B_OK)
		return status;
	status = gOps->remove_dir(&gVolume, &dir->node, name);
	put_vnode(&gVolume, dir->id);
	return status;
}


static status_t
fs_mkdir(const char* path)
{
	Vnode* dir;
	char name[B_FILE_NAME_LENGTH];
	status_t status = split_path(path, &dir, name);
	if (status != B_OK)
		return status;
	status = gOps->create_dir(&gVolume, &dir->node, name, 0755);
	put_vnode(&gVolume, dir->id);
	return status;
}


static status_t
fs_rename(const char* from, const char* to)
{
	Vnode* fromDir;
	Vnode* toDir;
	char fromName[B_FILE_NAME_LENGTH];
	char toName[B_FILE_NAME_LENGTH];
	status_t status = split_path(from, &fromDir, fromName);
	if (status != B_OK)
		return status;
	status = split_path(to, &toDir, toName);
	if (status != B_OK) {
		put_vnode(&gVolume, fromDir->id);
		return status;
	}
	status = gOps->rename(&gVolume, &fromDir->node, fromName, &toDir->node,
		toName);
	put_vnode(&gVolume, fromDir->id);
	put_vnode(&gVolume, toDir->id);
	return status;
}


static status_t
fs_write_stat(const char* path, const struct stat* st, uint32 mask)
{
	Vnode* vnode;
	status_t status = lookup_path(path, &vnode);
	if (status != B_OK)
		return status;
	status = gOps->write_stat(&gVolume, &vnode->node, st, mask);
	put_vnode(&gVolume, vnode->id);
	return status;
}


// Copies data into a new file the way Tracker's CopyFile() does: create the
// file O_RDWR, write the data, then set permissions, modification and
// creation time on the still-open file, and close it.
static status_t
fs_copy_like_tracker(const char* path, const void* data, size_t length,
	mode_t mode, time_t time)
{
	Vnode* dir;
	char name[B_FILE_NAME_LENGTH];
	status_t status = split_path(path, &dir, name);
	if (status != B_OK)
		return status;
	void* cookie;
	ino_t id;
	status = gOps->create(&gVolume, &dir->node, name, O_RDWR | O_CREAT,
		0644, &cookie, &id);
	put_vnode(&gVolume, dir->id);
	if (status != B_OK)
		return status;
	Vnode* vnode = find_vnode(id);
	size_t written = length;
	status = gOps->write(&gVolume, &vnode->node, cookie, 0, data, &written);
	if (status == B_OK && written != length)
		status = B_IO_ERROR;

	struct stat st;
	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFREG | mode;
	st.st_mtim.tv_sec = time;
	st.st_crtim.tv_sec = time;
	status_t stepStatus = gOps->write_stat(&gVolume, &vnode->node, &st,
		B_STAT_MODE);
	if (status == B_OK)
		status = stepStatus;
	stepStatus = gOps->write_stat(&gVolume, &vnode->node, &st,
		B_STAT_MODIFICATION_TIME);
	if (status == B_OK)
		status = stepStatus;
	stepStatus = gOps->write_stat(&gVolume, &vnode->node, &st,
		B_STAT_CREATION_TIME);
	if (status == B_OK)
		status = stepStatus;

	stepStatus = gOps->close(&gVolume, &vnode->node, cookie);
	if (status == B_OK)
		status = stepStatus;
	gOps->free_cookie(&gVolume, &vnode->node, cookie);
	put_vnode(&gVolume, id);
	return status;
}


static const char*
status_name(status_t status)
{
	switch (status) {
		case B_OK: return "B_OK";
		case B_ENTRY_NOT_FOUND: return "B_ENTRY_NOT_FOUND";
		case B_FILE_EXISTS: return "B_FILE_EXISTS";
		case B_IS_A_DIRECTORY: return "B_IS_A_DIRECTORY";
		case B_NOT_A_DIRECTORY: return "B_NOT_A_DIRECTORY";
		case B_DIRECTORY_NOT_EMPTY: return "B_DIRECTORY_NOT_EMPTY";
		case B_PERMISSION_DENIED: return "B_PERMISSION_DENIED";
		case B_READ_ONLY_DEVICE: return "B_READ_ONLY_DEVICE";
		case B_BAD_VALUE: return "B_BAD_VALUE";
		case B_IO_ERROR: return "B_IO_ERROR";
		case B_NO_MEMORY: return "B_NO_MEMORY";
		case SMB2_DISCONNECTED: return "SMB2_DISCONNECTED";
		default: {
			static char buffer[32];
			snprintf(buffer, sizeof(buffer), "0x%08x", (unsigned)status);
			return buffer;
		}
	}
}

#define CHECK_STATUS(status, expected, what) \
	CHECK((status) == (expected), "%s: got %s, expected %s", what, \
		status_name(status), status_name(expected))


// #pragma mark - scenario


static void
fill_pattern(uint8* buffer, size_t length, uint32 seed)
{
	uint32 x = seed;
	for (size_t i = 0; i < length; i++) {
		x = x * 1103515245 + 12345;
		buffer[i] = (uint8)(x >> 16);
	}
}


static int
run_scenario(const char* localRoot)
{
	status_t status;
	struct stat st;
	char base[64], path[512], path2[512];
	snprintf(base, sizeof(base), "fshost-%d", (int)getpid());

	printf("== scenario in %s ==\n", base);

	// root
	status = fs_stat("", &st);
	CHECK_STATUS(status, B_OK, "stat root");
	CHECK(S_ISDIR(st.st_mode), "root is not a directory");
	int count;
	status = fs_list("", &count, false);
	CHECK_STATUS(status, B_OK, "list root");
	CHECK(count >= 2, "root listing too short (%d)", count);

	// mkdir
	status = fs_mkdir(base);
	CHECK_STATUS(status, B_OK, "mkdir base");
	status = fs_mkdir(base);
	CHECK_STATUS(status, B_FILE_EXISTS, "mkdir existing");
	status = fs_stat(base, &st);
	CHECK(status == B_OK && S_ISDIR(st.st_mode), "stat base");

	// The sequence that crashed the VM: create, stat (vnode cached),
	// unlink while the vnode is still cached, later unmount.
	snprintf(path, sizeof(path), "%s/crash.txt", base);
	status = fs_write_file(path, "hello from haiku\n", 17, O_WRONLY | O_TRUNC);
	CHECK_STATUS(status, B_OK, "write crash.txt");
	status = fs_stat(path, &st);
	CHECK(status == B_OK && st.st_size == 17, "stat crash.txt");
	uint8* data; size_t length;
	status = fs_read_file(path, &data, &length, false);
	CHECK(status == B_OK && length == 17 && memcmp(data, "hello from haiku\n", 17) == 0, "read crash.txt");
	free(data);
	status = fs_unlink(path);
	CHECK_STATUS(status, B_OK, "unlink crash.txt");
	status = fs_stat(path, &st);
	CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "stat removed crash.txt");
	CHECK(find_vnode(0) == NULL, "sanity");

	// files of various sizes, read back through read() and read_pages()
	static const size_t kSizes[] = {0, 1, 4097, 65536, 1024 * 1024 + 5};
	for (size_t i = 0; i < sizeof(kSizes) / sizeof(kSizes[0]); i++) {
		size_t size = kSizes[i];
		snprintf(path, sizeof(path), "%s/f%lu", base, (unsigned long)size);
		uint8* pattern = (uint8*)malloc(size + 1);
		fill_pattern(pattern, size, (uint32)size + 7);
		status = fs_write_file(path, pattern, size, O_WRONLY | O_TRUNC);
		CHECK_STATUS(status, B_OK, "write file");
		status = fs_stat(path, &st);
		CHECK(status == B_OK && (size_t)st.st_size == size,
			"size mismatch for %s: %lld", path, (long long)st.st_size);
		status = fs_read_file(path, &data, &length, i % 2 == 0);
		CHECK(status == B_OK && length == size
			&& memcmp(data, pattern, size) == 0, "content mismatch %s", path);
		free(data);
		if (localRoot != NULL) {
			char local[1024];
			snprintf(local, sizeof(local), "%s/%s", localRoot, path);
			int fd = open(local, O_RDONLY);
			CHECK(fd >= 0, "local open %s", local);
			if (fd >= 0) {
				uint8* localData = (uint8*)malloc(size + 1);
				ssize_t got = read(fd, localData, size + 1);
				CHECK(got == (ssize_t)size && memcmp(localData, pattern, size) == 0,
					"local content mismatch %s", local);
				free(localData);
				close(fd);
			}
		}
		free(pattern);
	}

	// append and truncate
	snprintf(path, sizeof(path), "%s/f1", base);
	status = fs_write_file(path, "APPEND", 6, O_WRONLY | O_APPEND);
	CHECK_STATUS(status, B_OK, "append");
	status = fs_stat(path, &st);
	CHECK(status == B_OK && st.st_size == 7, "append size %lld", (long long)st.st_size);
	st.st_size = 3;
	status = fs_write_stat(path, &st, B_STAT_SIZE);
	CHECK_STATUS(status, B_OK, "truncate via write_stat");
	status = fs_stat(path, &st);
	CHECK(status == B_OK && st.st_size == 3, "truncated size %lld", (long long)st.st_size);
	st.st_mtim.tv_sec = 1234567890;
	st.st_mtim.tv_nsec = 0;
	status = fs_write_stat(path, &st, B_STAT_MODIFICATION_TIME);
	CHECK_STATUS(status, B_OK, "set mtime");
	status = fs_stat(path, &st);
	CHECK(status == B_OK && st.st_mtim.tv_sec == 1234567890, "mtime %lld", (long long)st.st_mtim.tv_sec);
	st.st_mode = S_IFREG | 0444;
	status = fs_write_stat(path, &st, B_STAT_MODE);
	CHECK_STATUS(status, B_OK, "set read-only");
	status = fs_stat(path, &st);
	CHECK(status == B_OK && (st.st_mode & S_IWUSR) == 0, "read-only mode %o", st.st_mode);
	st.st_mode = S_IFREG | 0644;
	status = fs_write_stat(path, &st, B_STAT_MODE);
	CHECK_STATUS(status, B_OK, "clear read-only");

	// Copy tools write the data, then set permissions and times while the
	// file is still open, then close it. With the data still in the file
	// cache, it must reach the server even though the file became read-only,
	// and the times must survive the write-back. Verified by another client.
	{
		static const char kReadOnlyText[]
			= "read-only file copied the way Tracker copies it\n";
		static const char kWritableText[]
			= "writable file copied the way Tracker copies it\n";
		const time_t kTime = 1710609208;	// 2024-03-16 17:13:28 UTC
		const uint64 kFileTime = ((uint64)kTime + 11644473600ULL) * 10000000ULL;
		char roPath[512], rwPath[512];
		snprintf(roPath, sizeof(roPath), "%s/copy-ro.txt", base);
		snprintf(rwPath, sizeof(rwPath), "%s/copy-rw.txt", base);

		gDeferWrites = true;
		status = fs_copy_like_tracker(roPath, kReadOnlyText,
			strlen(kReadOnlyText), 0444, kTime);
		CHECK_STATUS(status, B_OK, "tracker-style copy of a read-only file");
		status = fs_copy_like_tracker(rwPath, kWritableText,
			strlen(kWritableText), 0644, kTime);
		CHECK_STATUS(status, B_OK, "tracker-style copy of a writable file");
		gDeferWrites = false;

		smb2::Connection other;
		smb2::Credentials credentials;
		credentials.user = gUser;
		credentials.password = gPassword;
		smb2::Options options;
		status = other.Init(gServer, 445, gShare, credentials, options);
		if (status == B_OK)
			status = other.Connect();
		CHECK_STATUS(status, B_OK, "verification client connect");

		smb2::FileInfo info;
		status = other.QueryPathInfo(roPath, info);
		CHECK(status == B_OK && info.endOfFile == strlen(kReadOnlyText),
			"read-only copy on the server: %s, %llu bytes, expected %lu",
			status_name(status), (unsigned long long)info.endOfFile,
			(unsigned long)strlen(kReadOnlyText));
		CHECK(status == B_OK && (info.attributes & smb2::FILE_ATTRIBUTE_READONLY) != 0,
			"read-only copy lost its read-only attribute (%#x)",
			(unsigned)info.attributes);
		CHECK(status == B_OK && info.lastWriteTime / 10000000ULL
				== kFileTime / 10000000ULL,
			"read-only copy modification time %llu, expected %llu",
			(unsigned long long)(info.lastWriteTime / 10000000ULL),
			(unsigned long long)(kFileTime / 10000000ULL));

		status = other.QueryPathInfo(rwPath, info);
		CHECK(status == B_OK && info.endOfFile == strlen(kWritableText),
			"writable copy on the server: %s, %llu bytes, expected %lu",
			status_name(status), (unsigned long long)info.endOfFile,
			(unsigned long)strlen(kWritableText));
		CHECK(status == B_OK && info.lastWriteTime / 10000000ULL
				== kFileTime / 10000000ULL,
			"writable copy modification time %llu, expected %llu",
			(unsigned long long)(info.lastWriteTime / 10000000ULL),
			(unsigned long long)(kFileTime / 10000000ULL));

		if (localRoot != NULL) {
			const char* paths[2] = { roPath, rwPath };
			const char* texts[2] = { kReadOnlyText, kWritableText };
			for (int i = 0; i < 2; i++) {
				char local[1024];
				snprintf(local, sizeof(local), "%s/%s", localRoot, paths[i]);
				char buffer[256];
				int fd = open(local, O_RDONLY);
				ssize_t got = fd >= 0 ? read(fd, buffer, sizeof(buffer)) : -1;
				if (fd >= 0)
					close(fd);
				CHECK(got == (ssize_t)strlen(texts[i])
					&& memcmp(buffer, texts[i], got) == 0,
					"server-side content of %s (%ld bytes)", paths[i],
					(long)got);
			}
		}
		other.Disconnect();
		gDeferWrites = false;

		// Data that cannot be written any more must be reported by close()
		// instead of being dropped silently: another client deletes the
		// file and the connection drops before the cached data is written.
		{
			char lostPath[512];
			snprintf(lostPath, sizeof(lostPath), "%s/lost.txt", base);
			Vnode* dir;
			char name[B_FILE_NAME_LENGTH];
			status = split_path(lostPath, &dir, name);
			CHECK_STATUS(status, B_OK, "lookup dir for lost.txt");
			void* cookie;
			ino_t id;
			status = gOps->create(&gVolume, &dir->node, name, O_RDWR | O_CREAT,
				0644, &cookie, &id);
			put_vnode(&gVolume, dir->id);
			CHECK_STATUS(status, B_OK, "create lost.txt");
			Vnode* vnode = find_vnode(id);
			gDeferWrites = true;
			size_t written = 5;
			status = gOps->write(&gVolume, &vnode->node, cookie, 0, "data\n",
				&written);
			gDeferWrites = false;
			CHECK_STATUS(status, B_OK, "cached write to lost.txt");
			status = other.Connect();
			if (status == B_OK)
				status = other.DeletePath(lostPath, false);
			CHECK_STATUS(status, B_OK, "other client deletes lost.txt");
			other.Disconnect();
			Volume* volume = (Volume*)gVolume.private_volume;
			volume->GetConnection()->Disconnect();
			status = gOps->close(&gVolume, &vnode->node, cookie);
			CHECK(status != B_OK, "close() reported success although the "
				"cached data could not be written");
			gOps->free_cookie(&gVolume, &vnode->node, cookie);
			put_vnode(&gVolume, id);
		}

		// a read-only file must stay deletable after making it writable
		st.st_mode = S_IFREG | 0644;
		status = fs_write_stat(roPath, &st, B_STAT_MODE);
		CHECK_STATUS(status, B_OK, "make read-only copy writable");
		status = fs_unlink(roPath);
		CHECK_STATUS(status, B_OK, "unlink read-only copy");
		status = fs_unlink(rwPath);
		CHECK_STATUS(status, B_OK, "unlink writable copy");
	}

	// directory listing primes the inode cache; entries get stable ids
	snprintf(path, sizeof(path), "%s/dir", base);
	status = fs_mkdir(path);
	CHECK_STATUS(status, B_OK, "mkdir dir");
	for (int i = 0; i < 50; i++) {
		snprintf(path, sizeof(path), "%s/dir/e%02d", base, i);
		status = fs_write_file(path, "x", 1, O_WRONLY | O_TRUNC);
		if (status != B_OK) {
			CHECK_STATUS(status, B_OK, "create entry");
			break;
		}
	}
	snprintf(path, sizeof(path), "%s/dir", base);
	status = fs_list(path, &count, false);
	CHECK_STATUS(status, B_OK, "list dir");
	CHECK(count == 52, "listed %d entries, expected 52", count);
	snprintf(path, sizeof(path), "%s/dir/e07", base);
	struct stat st1, st2;
	fs_stat(path, &st1);
	evict_unused_vnodes();
	fs_stat(path, &st2);
	CHECK(st1.st_ino == st2.st_ino, "inode id changed after eviction");

	// rename a directory with cached children, then access a child
	snprintf(path, sizeof(path), "%s/dir", base);
	snprintf(path2, sizeof(path2), "%s/dir2", base);
	status = fs_rename(path, path2);
	CHECK_STATUS(status, B_OK, "rename dir");
	snprintf(path, sizeof(path), "%s/dir2/e07", base);
	status = fs_stat(path, &st);
	CHECK(status == B_OK && st.st_ino == st1.st_ino, "child after dir rename");
	snprintf(path, sizeof(path), "%s/dir/e07", base);
	status = fs_stat(path, &st);
	CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "old path after dir rename");

	// rename over an existing file
	snprintf(path, sizeof(path), "%s/dir2/e01", base);
	snprintf(path2, sizeof(path2), "%s/dir2/e02", base);
	fs_stat(path2, &st2);
	status = fs_rename(path, path2);
	CHECK_STATUS(status, B_OK, "rename over existing");
	status = fs_stat(path, &st);
	CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "renamed source gone");
	status = fs_stat(path2, &st);
	CHECK_STATUS(status, B_OK, "rename target exists");

	// rmdir non-empty, unlink a directory, rmdir a file
	snprintf(path, sizeof(path), "%s/dir2", base);
	status = fs_rmdir(path);
	CHECK_STATUS(status, B_DIRECTORY_NOT_EMPTY, "rmdir non-empty");
	status = fs_unlink(path);
	CHECK_STATUS(status, B_IS_A_DIRECTORY, "unlink directory");
	snprintf(path, sizeof(path), "%s/dir2/e03", base);
	status = fs_rmdir(path);
	CHECK_STATUS(status, B_NOT_A_DIRECTORY, "rmdir file");

	// external modification by another client: remove a file behind our
	// back and replace another one by a directory, then look them up again
	{
		smb2::Connection other;
		smb2::Credentials credentials;
		credentials.user = gUser;
		credentials.password = gPassword;
		smb2::Options options;
		status = other.Init(gServer, 445, gShare, credentials, options);
		if (status == B_OK)
			status = other.Connect();
		CHECK_STATUS(status, B_OK, "second client connect");

		snprintf(path, sizeof(path), "%s/dir2/e05", base);
		fs_stat(path, &st);
		status = other.DeletePath(path, false);
		CHECK_STATUS(status, B_OK, "other client delete");
		// cached for up to the cache timeout; wait it out
		smb2::Snooze(2500000);
		status = fs_stat(path, &st);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "externally removed file");

		snprintf(path, sizeof(path), "%s/dir2/e06", base);
		fs_stat(path, &st);
		status = other.DeletePath(path, false);
		CHECK_STATUS(status, B_OK, "other client delete e06");
		status = other.CreateDirectoryPath(path, NULL);
		CHECK_STATUS(status, B_OK, "other client mkdir e06");
		smb2::Snooze(2500000);
		status = fs_stat(path, &st);
		CHECK(status == B_OK && S_ISDIR(st.st_mode), "type change detected");
		status = other.DeletePath(path, true);
		CHECK_STATUS(status, B_OK, "other client rmdir e06");
		other.Disconnect();
	}

	// virtual BEOS:TYPE attribute from the file extension
	{
		snprintf(path, sizeof(path), "%s/clip.MP4", base);
		status = fs_write_file(path, "x", 1, O_WRONLY | O_TRUNC);
		CHECK_STATUS(status, B_OK, "create clip.MP4");
		Vnode* vnode;
		status = lookup_path(path, &vnode);
		CHECK_STATUS(status, B_OK, "lookup clip.MP4");
		void* dirCookie;
		status = gOps->open_attr_dir(&gVolume, &vnode->node, &dirCookie);
		CHECK_STATUS(status, B_OK, "open_attr_dir");
		char buffer[256];
		uint32 num = 4;
		status = gOps->read_attr_dir(&gVolume, &vnode->node, dirCookie,
			(struct dirent*)buffer, sizeof(buffer), &num);
		CHECK(status == B_OK && num == 1
			&& strcmp(((struct dirent*)buffer)->d_name, "BEOS:TYPE") == 0,
			"attribute directory lists BEOS:TYPE (%s, %u)", status_name(status), num);
		num = 4;
		gOps->read_attr_dir(&gVolume, &vnode->node, dirCookie,
			(struct dirent*)buffer, sizeof(buffer), &num);
		CHECK(num == 0, "attribute directory ends");
		gOps->free_attr_dir_cookie(&gVolume, &vnode->node, dirCookie);
		void* attrCookie;
		status = gOps->open_attr(&gVolume, &vnode->node, "BEOS:TYPE", O_RDONLY,
			&attrCookie);
		CHECK_STATUS(status, B_OK, "open_attr BEOS:TYPE");
		if (status == B_OK) {
			struct stat attrStat;
			gOps->read_attr_stat(&gVolume, &vnode->node, attrCookie, &attrStat);
			size_t length = sizeof(buffer);
			status = gOps->read_attr(&gVolume, &vnode->node, attrCookie, 0,
				buffer, &length);
			CHECK(status == B_OK && length == 10 && strcmp(buffer, "video/mp4") == 0
				&& attrStat.st_size == 10 && attrStat.st_type == B_MIME_STRING_TYPE,
				"BEOS:TYPE content (%s, %lu)", buffer, (unsigned long)length);
			gOps->free_attr_cookie(&gVolume, &vnode->node, attrCookie);
		}
		status = gOps->open_attr(&gVolume, &vnode->node, "BEOS:TYPE", O_RDWR,
			&attrCookie);
		CHECK_STATUS(status, B_READ_ONLY_DEVICE, "open_attr for writing");
		status = gOps->open_attr(&gVolume, &vnode->node, "Other:Attr", O_RDONLY,
			&attrCookie);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "open unknown attribute");
		put_vnode(&gVolume, vnode->id);
		fs_unlink(path);
		// no extension: no attribute
		snprintf(path, sizeof(path), "%s/README", base);
		fs_write_file(path, "x", 1, O_WRONLY | O_TRUNC);
		status = lookup_path(path, &vnode);
		CHECK_STATUS(status, B_OK, "lookup README");
		status = gOps->open_attr(&gVolume, &vnode->node, "BEOS:TYPE", O_RDONLY,
			&attrCookie);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "no type for unknown extension");
		put_vnode(&gVolume, vnode->id);
		fs_unlink(path);
	}

	// simulated connection loss: open handles must be re-established
	{
		snprintf(path, sizeof(path), "%s/f65536", base);
		Vnode* vnode;
		status = lookup_path(path, &vnode);
		CHECK_STATUS(status, B_OK, "lookup for reconnect test");
		void* cookie;
		status = gOps->open(&gVolume, &vnode->node, O_RDWR, &cookie);
		CHECK_STATUS(status, B_OK, "open for reconnect test");
		Volume* volume = (Volume*)gVolume.private_volume;
		volume->GetConnection()->Disconnect();
		uint8 buffer[100];
		size_t chunk = sizeof(buffer);
		status = gOps->read(&gVolume, &vnode->node, cookie, 100, buffer,
			&chunk);
		CHECK_STATUS(status, B_OK, "read after reconnect");
		CHECK(chunk == 100, "read after reconnect length %lu",
			(unsigned long)chunk);
		uint8 expected[65536];
		fill_pattern(expected, 65536, 65536 + 7);
		CHECK(memcmp(buffer, expected + 100, 100) == 0,
			"read after reconnect content");
		chunk = 5;
		status = gOps->write(&gVolume, &vnode->node, cookie, 0, "RECON",
			&chunk);
		CHECK_STATUS(status, B_OK, "write after reconnect");
		gOps->close(&gVolume, &vnode->node, cookie);
		gOps->free_cookie(&gVolume, &vnode->node, cookie);
		put_vnode(&gVolume, vnode->id);
		volume->GetConnection()->Disconnect();
		status = fs_stat(path, &st);
		CHECK_STATUS(status, B_OK, "stat after reconnect");
	}

	// cleanup
	for (int i = 0; i < 50; i++) {
		snprintf(path, sizeof(path), "%s/dir2/e%02d", base, i);
		fs_unlink(path);
	}
	snprintf(path, sizeof(path), "%s/dir2", base);
	status = fs_rmdir(path);
	CHECK_STATUS(status, B_OK, "rmdir dir2");
	for (size_t i = 0; i < sizeof(kSizes) / sizeof(kSizes[0]); i++) {
		snprintf(path, sizeof(path), "%s/f%lu", base, (unsigned long)kSizes[i]);
		status = fs_unlink(path);
		CHECK_STATUS(status, B_OK, "unlink file");
	}
	status = fs_rmdir(base);
	CHECK_STATUS(status, B_OK, "rmdir base");

	printf("== scenario done: %d vnodes cached, %d notifications ==\n",
		gVnodeCount, gNotifications);
	return gFailures;
}


int
main(int argc, char** argv)
{
	const char* localRoot = NULL;
	const char* mountArgs = NULL;
	int i = 1;
	for (; i < argc; i++) {
		if (strcmp(argv[i], "--local-root") == 0 && i + 1 < argc)
			localRoot = argv[++i];
		else if (strcmp(argv[i], "-v") == 0)
			gVerbose = true;
		else
			break;
	}
	if (i < argc)
		mountArgs = argv[i];
	{
		static char server[256], share[256], user[256], password[256];
		const char* p = mountArgs;
		while (*p == '/') p++;
		sscanf(p, "%255[^/]/%255s", server, share);
		const char* u = strstr(mountArgs, "user=");
		const char* pw = strstr(mountArgs, "password=");
		if (u != NULL) sscanf(u + 5, "%255s", user);
		if (pw != NULL) sscanf(pw + 9, "%255s", password);
		gServer = server; gShare = share; gUser = user; gPassword = password;
	}
	if (mountArgs == NULL) {
		fprintf(stderr, "usage: fshost [--local-root dir] [-v] "
			"\"//server/share user=... password=...\"\n");
		return 1;
	}

	file_system_module_info* module = (file_system_module_info*)modules[0];
	module->info.std_ops(B_MODULE_INIT);

	memset(&gVolume, 0, sizeof(gVolume));
	gVolume.id = 42;
	status_t status = module->mount(&gVolume, NULL, 0, mountArgs, &gRootID);
	if (status != B_OK) {
		printf("mount failed: %s\n", status_name(status));
		return 1;
	}
	Vnode* root = find_vnode(gRootID);
	CHECK(root != NULL && root->refCount == 1, "root vnode not published");
	gOps = root->node.ops;

	struct fs_info info;
	status = gVolume.ops->read_fs_info(&gVolume, &info);
	CHECK_STATUS(status, B_OK, "read_fs_info");
	printf("mounted %s (%s), %lld blocks of %lld bytes\n", info.volume_name,
		info.device_name, (long long)info.total_blocks,
		(long long)info.block_size);

	int failures = run_scenario(localRoot);

	// unmount: free all vnodes but the root (mirrors fs_unmount), then
	// call the unmount hook
	printf("== unmount ==\n");
	Vnode* vnode = gVnodes;
	while (vnode != NULL) {
		Vnode* next = vnode->next;
		if (vnode->id != gRootID) {
			CHECK(vnode->refCount == 0, "vnode %lld still referenced (%d)",
				(long long)vnode->id, vnode->refCount);
			free_vnode(vnode);
		}
		vnode = next;
	}
	gVolume.ops->unmount(&gVolume);
	// Between unmount() and the release of the root vnode, the VFS may still
	// call hooks on the root (entry_ref lookups racing the unmount
	// notification); they must fail cleanly.
	{
		ino_t id;
		status = root->node.ops->lookup(&gVolume, &root->node, "testdata", &id);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "lookup on unmounted root");
		status = root->node.ops->access(&gVolume, &root->node, 1);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "access on unmounted root");
		struct stat st;
		status = root->node.ops->read_stat(&gVolume, &root->node, &st);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "read_stat on unmounted root");
		void* cookie;
		status = root->node.ops->open_dir(&gVolume, &root->node, &cookie);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "open_dir on unmounted root");
	}
	// ... and finally the VFS releases the root vnode (mirrors ~fs_mount).
	root->node.ops->put_vnode(&gVolume, &root->node, false);
	module->info.std_ops(B_MODULE_UNINIT);
	free(root);

	CHECK(gFileCaches == 0, "%d file caches leaked", gFileCaches);
	printf("== %d failure(s) ==\n", failures + gFailures - failures);
	return gFailures == 0 ? 0 : 1;
}
