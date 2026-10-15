/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Thin platform abstraction: logging, time, randomness, locking. The
 * implementation differs between the Haiku kernel and userland.
 */
#ifndef SMB2_PLATFORM_H
#define SMB2_PLATFORM_H

#include "Types.h"

#include <stdarg.h>

#ifdef _KERNEL_MODE
#	include <KernelExport.h>
#	include <lock.h>
#	include <util/kernel_cpp.h>
#else
#	include <pthread.h>
#	include <new>
#endif


namespace smb2 {


void Log(const char* format, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	;
void LogV(const char* format, va_list args);

// Debug tracing; enabled at runtime via SetTraceEnabled().
void Trace(const char* format, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)))
#endif
	;
void SetTraceEnabled(bool enabled);
bool TraceEnabled();

// Monotonic time in microseconds.
bigtime_t SystemTime();
// Wall clock time in microseconds since the Unix epoch.
int64 RealTimeUsecs();
// Fill the buffer with cryptographically useful random bytes.
void RandomBytes(void* buffer, size_t length);
void Snooze(bigtime_t microseconds);

// Current effective uid/gid (used for stat information).
uint32 CurrentUserID();
uint32 CurrentGroupID();


class Mutex {
public:
								Mutex(const char* name);
								~Mutex();

			void				Lock();
			void				Unlock();

private:
#ifdef _KERNEL_MODE
			mutex				fLock;
#else
			pthread_mutex_t		fLock;
#endif
};


class MutexLocker {
public:
	MutexLocker(Mutex& lock)
		:
		fLock(&lock),
		fLocked(true)
	{
		fLock->Lock();
	}

	MutexLocker(Mutex* lock)
		:
		fLock(lock),
		fLocked(lock != NULL)
	{
		if (fLock != NULL)
			fLock->Lock();
	}

	~MutexLocker()
	{
		Unlock();
	}

	void Unlock()
	{
		if (fLocked) {
			fLock->Unlock();
			fLocked = false;
		}
	}

	void Lock()
	{
		if (!fLocked && fLock != NULL) {
			fLock->Lock();
			fLocked = true;
		}
	}

private:
			Mutex*				fLock;
			bool				fLocked;
};


class RWLock {
public:
								RWLock(const char* name);
								~RWLock();

			void				ReadLock();
			void				ReadUnlock();
			void				WriteLock();
			void				WriteUnlock();

private:
#ifdef _KERNEL_MODE
			rw_lock				fLock;
#else
			pthread_rwlock_t	fLock;
#endif
};


class ReadLocker {
public:
	ReadLocker(RWLock& lock) : fLock(lock), fLocked(true) { fLock.ReadLock(); }
	~ReadLocker() { Unlock(); }
	void Unlock() { if (fLocked) { fLock.ReadUnlock(); fLocked = false; } }
private:
	RWLock&	fLock;
	bool	fLocked;
};


class WriteLocker {
public:
	WriteLocker(RWLock& lock) : fLock(lock), fLocked(true) { fLock.WriteLock(); }
	~WriteLocker() { Unlock(); }
	void Unlock() { if (fLocked) { fLock.WriteUnlock(); fLocked = false; } }
private:
	RWLock&	fLock;
	bool	fLocked;
};


}	// namespace smb2


#endif	// SMB2_PLATFORM_H
