/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef FILE_CACHE_COMPAT_H
#define FILE_CACHE_COMPAT_H


#include <fs_cache.h>


/*!	file_cache_read() and file_cache_write() have a "cookie" argument up to
	R1/beta6; Haiku nightlies after 2026-09-29 dropped it. These call
	whichever of the two the headers declare, so that the file system builds
	for both: the version with the cookie is preferred (the int argument), the
	other one is used when that does not compile (SFINAE).
*/
namespace FileCacheCompat {


template<typename Function, typename Buffer>
static inline auto
Call(Function function, void* cache, void* cookie, off_t offset,
	Buffer buffer, size_t* _size, int)
	-> decltype(function(cache, cookie, offset, buffer, _size))
{
	return function(cache, cookie, offset, buffer, _size);
}


template<typename Function, typename Buffer>
static inline auto
Call(Function function, void* cache, void* /*cookie*/, off_t offset,
	Buffer buffer, size_t* _size, long)
	-> decltype(function(cache, offset, buffer, _size))
{
	return function(cache, offset, buffer, _size);
}


}	// namespace FileCacheCompat


static inline status_t
compat_file_cache_read(void* cache, void* cookie, off_t offset, void* buffer,
	size_t* _size)
{
	return FileCacheCompat::Call(&file_cache_read, cache, cookie, offset,
		buffer, _size, 0);
}


static inline status_t
compat_file_cache_write(void* cache, void* cookie, off_t offset,
	const void* buffer, size_t* _size)
{
	return FileCacheCompat::Call(&file_cache_write, cache, cookie, offset,
		buffer, _size, 0);
}


#endif	// FILE_CACHE_COMPAT_H
