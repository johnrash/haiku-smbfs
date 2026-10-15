/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Basic types and error codes. On Haiku (kernel or userland) the native
 * definitions are used; elsewhere compatible definitions are provided so the
 * protocol core can be built and tested on other POSIX systems.
 */
#ifndef SMB2_TYPES_H
#define SMB2_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>


#ifdef __HAIKU__
#	include <SupportDefs.h>
#	include <Errors.h>
#	define SMB2_ERRNO(e) (e)
#else
#	include <limits.h>

typedef int32_t status_t;
typedef int64_t bigtime_t;
typedef int8_t int8;
typedef uint8_t uint8;
typedef int16_t int16;
typedef uint16_t uint16;
typedef int32_t int32;
typedef uint32_t uint32;
typedef int64_t int64;
typedef uint64_t uint64;

// Haiku compatible error codes.
#	define B_GENERAL_ERROR_BASE		INT_MIN
#	define B_OS_ERROR_BASE			(B_GENERAL_ERROR_BASE + 0x1000)
#	define B_STORAGE_ERROR_BASE		(B_GENERAL_ERROR_BASE + 0x6000)
#	define B_POSIX_ERROR_BASE		(B_GENERAL_ERROR_BASE + 0x7000)

enum {
	B_NO_MEMORY = B_GENERAL_ERROR_BASE,
	B_IO_ERROR,
	B_PERMISSION_DENIED,
	B_BAD_INDEX,
	B_BAD_TYPE,
	B_BAD_VALUE,
	B_MISMATCHED_VALUES,
	B_NAME_NOT_FOUND,
	B_NAME_IN_USE,
	B_TIMED_OUT,
	B_INTERRUPTED,
	B_WOULD_BLOCK,
	B_CANCELED,
	B_NO_INIT,
	B_NOT_INITIALIZED = B_NO_INIT,
	B_BUSY,
	B_NOT_ALLOWED,
	B_BAD_DATA,
	B_DONT_DO_THAT,

	B_ERROR = -1,
	B_OK = 0,
	B_NO_ERROR = 0,

	B_BAD_ADDRESS = B_OS_ERROR_BASE + 0x301,

	B_FILE_ERROR = B_STORAGE_ERROR_BASE,
	B_FILE_EXISTS = B_STORAGE_ERROR_BASE + 2,
	B_ENTRY_NOT_FOUND,
	B_NAME_TOO_LONG,
	B_NOT_A_DIRECTORY,
	B_DIRECTORY_NOT_EMPTY,
	B_DEVICE_FULL,
	B_READ_ONLY_DEVICE,
	B_IS_A_DIRECTORY,
	B_NO_MORE_FDS,
	B_CROSS_DEVICE_LINK,
	B_LINK_LIMIT,
	B_BUSY_PARTITION,
	B_UNSUPPORTED,
	B_PARTITION_TOO_SMALL,
	B_PARTIAL_READ,
	B_PARTIAL_WRITE
};

#	define B_NOT_SUPPORTED	B_UNSUPPORTED
#	define SMB2_ERRNO(e)	(-(e))
#endif	// !__HAIKU__

// Returned by the connection layer when the transport connection was lost.
#define SMB2_DISCONNECTED	SMB2_ERRNO(ECONNRESET)

#ifndef B_NOT_SUPPORTED
#	define B_NOT_SUPPORTED	B_UNSUPPORTED
#endif


#endif	// SMB2_TYPES_H
