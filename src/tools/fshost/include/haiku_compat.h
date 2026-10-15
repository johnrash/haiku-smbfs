/*
 * Minimal emulation of the Haiku kernel interfaces used by the smbfs add-on,
 * so that the add-on's Volume/Inode/hook code can be compiled and exercised
 * as an ordinary userland program on other POSIX systems (with ASan etc).
 * This is only a test aid; it is not a complete or faithful VFS.
 */
#ifndef FSHOST_HAIKU_COMPAT_H
#define FSHOST_HAIKU_COMPAT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include "../../../smb2/Types.h"

// Haiku's stat has a creation time field; wrap the host structure.
struct haiku_stat {
	dev_t			st_dev;
	ino_t			st_ino;
	mode_t			st_mode;
	nlink_t			st_nlink;
	uid_t			st_uid;
	gid_t			st_gid;
	off_t			st_size;
	dev_t			st_rdev;
	blksize_t		st_blksize;
	struct timespec	st_atim;
	struct timespec	st_mtim;
	struct timespec	st_ctim;
	struct timespec	st_crtim;
	uint32			st_type;
	blkcnt_t		st_blocks;
};
#define stat haiku_stat

struct haiku_dirent {
	dev_t			d_dev;
	dev_t			d_pdev;
	ino_t			d_ino;
	ino_t			d_pino;
	unsigned short	d_reclen;
	char			d_name[];
};
#define dirent haiku_dirent
#define _DIRENT_H 1

#define S_ATTR				02000000000
#define B_MIME_STRING_TYPE	'MIMS'
#define B_PATH_NAME_LENGTH	1024
#define B_FILE_NAME_LENGTH	256
#define B_OS_NAME_LENGTH	32

#define B_MOUNT_READ_ONLY		1
#define B_MOUNT_VIRTUAL_DEVICE	2

#define B_FS_IS_READONLY		0x00000001
#define B_FS_IS_REMOVABLE		0x00000002
#define B_FS_IS_PERSISTENT		0x00000004
#define B_FS_IS_SHARED			0x00000008
#define B_FS_HAS_MIME			0x00010000
#define B_FS_HAS_ATTR			0x00020000
#define B_FS_HAS_QUERY			0x00040000

#define B_DEV_INVALID_IOCTL		(B_GENERAL_ERROR_BASE + 0xa000)
#define B_BUFFER_OVERFLOW		(B_GENERAL_ERROR_BASE + 0x7000 + 0x7f)

enum {
	B_STAT_MODE					= 0x0001,
	B_STAT_UID					= 0x0002,
	B_STAT_GID					= 0x0004,
	B_STAT_SIZE					= 0x0008,
	B_STAT_ACCESS_TIME			= 0x0010,
	B_STAT_MODIFICATION_TIME	= 0x0020,
	B_STAT_CREATION_TIME		= 0x0040,
	B_STAT_CHANGE_TIME			= 0x0080,
	B_STAT_INTERIM_UPDATE		= 0x1000
};

struct fs_info {
	dev_t	dev;
	ino_t	root;
	uint32	flags;
	off_t	block_size;
	off_t	io_size;
	off_t	total_blocks;
	off_t	free_blocks;
	off_t	total_nodes;
	off_t	free_nodes;
	char	device_name[128];
	char	volume_name[B_FILE_NAME_LENGTH];
	char	fsh_name[B_OS_NAME_LENGTH];
};

typedef int32 partition_id;
typedef int32 disk_job_id;
struct partition_data;
typedef struct selectsync selectsync;
typedef struct IORequest io_request;

typedef struct module_info {
	const char*	name;
	uint32		flags;
	status_t	(*std_ops)(int32, ...);
} module_info;

#define B_KEEP_LOADED	0x1
#define B_MODULE_INIT	1
#define B_MODULE_UNINIT	2

#define B_CURRENT_FS_API_VERSION "/v1"

typedef struct fs_volume fs_volume;
typedef struct fs_volume_ops fs_volume_ops;
typedef struct fs_vnode fs_vnode;
typedef struct fs_vnode_ops fs_vnode_ops;
typedef struct file_system_module_info file_system_module_info;

struct fs_volume {
	dev_t						id;
	partition_id				partition;
	int32						layer;
	void*						private_volume;
	fs_volume_ops*				ops;
	fs_volume*					sub_volume;
	fs_volume*					super_volume;
	file_system_module_info*	file_system;
	char*						file_system_name;
};

struct fs_vnode {
	void*			private_node;
	fs_vnode_ops*	ops;
};

struct fs_volume_ops {
	status_t (*unmount)(fs_volume* volume);
	status_t (*read_fs_info)(fs_volume* volume, struct fs_info* info);
	status_t (*write_fs_info)(fs_volume* volume, const struct fs_info* info, uint32 mask);
	status_t (*sync)(fs_volume* volume);
	status_t (*get_vnode)(fs_volume* volume, ino_t id, fs_vnode* vnode, int* _type, uint32* _flags, bool reenter);
	void* index_and_query_ops[13];
	status_t (*all_layers_mounted)(fs_volume* volume);
	status_t (*create_sub_vnode)(fs_volume* volume, ino_t id, fs_vnode* vnode);
	status_t (*delete_sub_vnode)(fs_volume* volume, fs_vnode* vnode);
};

struct fs_vnode_ops {
	status_t (*lookup)(fs_volume* volume, fs_vnode* dir, const char* name, ino_t* _id);
	status_t (*get_vnode_name)(fs_volume* volume, fs_vnode* vnode, char* buffer, size_t bufferSize);
	status_t (*put_vnode)(fs_volume* volume, fs_vnode* vnode, bool reenter);
	status_t (*remove_vnode)(fs_volume* volume, fs_vnode* vnode, bool reenter);
	bool (*can_page)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*read_pages)(fs_volume* volume, fs_vnode* vnode, void* cookie, off_t pos, const iovec* vecs, size_t count, size_t* _numBytes);
	status_t (*write_pages)(fs_volume* volume, fs_vnode* vnode, void* cookie, off_t pos, const iovec* vecs, size_t count, size_t* _numBytes);
	status_t (*io)(fs_volume* volume, fs_vnode* vnode, void* cookie, io_request* request);
	status_t (*cancel_io)(fs_volume* volume, fs_vnode* vnode, void* cookie, io_request* request);
	void* get_file_map;
	status_t (*ioctl)(fs_volume* volume, fs_vnode* vnode, void* cookie, uint32 op, void* buffer, size_t length);
	status_t (*set_flags)(fs_volume* volume, fs_vnode* vnode, void* cookie, int flags);
	void* select;
	void* deselect;
	status_t (*fsync)(fs_volume* volume, fs_vnode* vnode, bool dataOnly);
	void* read_symlink;
	void* create_symlink;
	void* link;
	status_t (*unlink)(fs_volume* volume, fs_vnode* dir, const char* name);
	status_t (*rename)(fs_volume* volume, fs_vnode* fromDir, const char* fromName, fs_vnode* toDir, const char* toName);
	status_t (*access)(fs_volume* volume, fs_vnode* vnode, int mode);
	status_t (*read_stat)(fs_volume* volume, fs_vnode* vnode, struct stat* stat);
	status_t (*write_stat)(fs_volume* volume, fs_vnode* vnode, const struct stat* stat, uint32 statMask);
	void* preallocate;
	status_t (*create)(fs_volume* volume, fs_vnode* dir, const char* name, int openMode, int perms, void** _cookie, ino_t* _newVnodeID);
	status_t (*open)(fs_volume* volume, fs_vnode* vnode, int openMode, void** _cookie);
	status_t (*close)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*free_cookie)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*read)(fs_volume* volume, fs_vnode* vnode, void* cookie, off_t pos, void* buffer, size_t* length);
	status_t (*write)(fs_volume* volume, fs_vnode* vnode, void* cookie, off_t pos, const void* buffer, size_t* length);
	status_t (*create_dir)(fs_volume* volume, fs_vnode* parent, const char* name, int perms);
	status_t (*remove_dir)(fs_volume* volume, fs_vnode* parent, const char* name);
	status_t (*open_dir)(fs_volume* volume, fs_vnode* vnode, void** _cookie);
	status_t (*close_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*free_dir_cookie)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*read_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie, struct dirent* buffer, size_t bufferSize, uint32* _num);
	status_t (*rewind_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*open_attr_dir)(fs_volume* volume, fs_vnode* vnode, void** _cookie);
	status_t (*close_attr_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*free_attr_dir_cookie)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*read_attr_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie, struct dirent* buffer, size_t bufferSize, uint32* _num);
	status_t (*rewind_attr_dir)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	void* create_attr;
	status_t (*open_attr)(fs_volume* volume, fs_vnode* vnode, const char* name, int openMode, void** _cookie);
	status_t (*close_attr)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*free_attr_cookie)(fs_volume* volume, fs_vnode* vnode, void* cookie);
	status_t (*read_attr)(fs_volume* volume, fs_vnode* vnode, void* cookie, off_t pos, void* buffer, size_t* length);
	void* write_attr;
	status_t (*read_attr_stat)(fs_volume* volume, fs_vnode* vnode, void* cookie, struct stat* stat);
	void* write_attr_stat;
	void* rename_attr;
	void* remove_attr;
	void* create_special_node;
	void* get_super_vnode;
	void* test_lock;
	void* acquire_lock;
	void* release_lock;
};

struct file_system_module_info {
	struct module_info	info;
	const char*			short_name;
	const char*			pretty_name;
	uint32				flags;
	void* identify_partition;
	void* scan_partition;
	void* free_identify_partition_cookie;
	void* free_partition_content_cookie;
	status_t (*mount)(fs_volume* volume, const char* device, uint32 flags, const char* args, ino_t* _rootVnodeID);
	void* rest[16];
};

// Fake VFS services implemented by fshost.cpp
extern "C" {
status_t new_vnode(fs_volume* volume, ino_t vnodeID, void* privateNode, fs_vnode_ops* ops);
status_t publish_vnode(fs_volume* volume, ino_t vnodeID, void* privateNode, fs_vnode_ops* ops, int type, uint32 flags);
status_t get_vnode(fs_volume* volume, ino_t vnodeID, void** _privateNode);
status_t put_vnode(fs_volume* volume, ino_t vnodeID);
status_t acquire_vnode(fs_volume* volume, ino_t vnodeID);
status_t remove_vnode(fs_volume* volume, ino_t vnodeID);
status_t unremove_vnode(fs_volume* volume, ino_t vnodeID);
status_t notify_entry_created(dev_t device, ino_t directory, const char* name, ino_t node);
status_t notify_entry_removed(dev_t device, ino_t directory, const char* name, ino_t node);
status_t notify_entry_moved(dev_t device, ino_t fromDirectory, const char* fromName, ino_t toDirectory, const char* toName, ino_t node);
status_t notify_stat_changed(dev_t device, ino_t directory, ino_t node, uint32 statFields);
void haiku_dprintf(const char* format, ...);
status_t user_memcpy(void* to, const void* from, size_t size);
void* file_cache_create(dev_t mountID, ino_t vnodeID, off_t size);
void file_cache_delete(void* cacheRef);
void file_cache_enable(void* cacheRef);
status_t file_cache_disable(void* cacheRef);
status_t file_cache_set_size(void* cacheRef, off_t size);
status_t file_cache_sync(void* cache);
status_t file_cache_read(void* cacheRef, void* cookie, off_t offset, void* bufferBase, size_t* _size);
status_t file_cache_write(void* cacheRef, void* cookie, off_t offset, const void* buffer, size_t* _size);
}

#define IS_USER_ADDRESS(x) (false)
#define dprintf haiku_dprintf

#endif	// FSHOST_HAIKU_COMPAT_H
