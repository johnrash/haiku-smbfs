/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Platform.h"

#include <stdio.h>
#include <string.h>

#ifdef _KERNEL_MODE
#	include <unistd.h>
// Declared here to avoid pulling in boot loader headers via util/Random.h.
extern "C" unsigned int secure_random_value(void);
extern "C" bigtime_t real_time_clock_usecs(void);

// The kernel exports mutex_lock() and mutex_unlock() as real functions in
// both release and debug (KDEBUG) builds. lock.h replaces them with inline
// fast paths calling _mutex_lock()/_mutex_unlock(), which only exist in
// release kernels: a module built that way fails to load on a nightly (debug)
// kernel with "No such device". Use the exported functions so that one binary
// works on both. (The rw_lock inlines are identical in both builds.)
#	ifdef mutex_lock
#		undef mutex_lock
#	endif
#	ifdef mutex_unlock
#		undef mutex_unlock
#	endif
#else
#	include <stdlib.h>
#	include <sys/time.h>
#	include <time.h>
#	include <unistd.h>
#	include <fcntl.h>
#endif


namespace smb2 {


static bool sTraceEnabled = false;


void
SetTraceEnabled(bool enabled)
{
	sTraceEnabled = enabled;
}


bool
TraceEnabled()
{
	return sTraceEnabled;
}


void
LogV(const char* format, va_list args)
{
	char buffer[512];
	vsnprintf(buffer, sizeof(buffer), format, args);
#ifdef _KERNEL_MODE
	dprintf("smbfs: %s", buffer);
#else
	fprintf(stderr, "smb2: %s", buffer);
#endif
}


void
Log(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	LogV(format, args);
	va_end(args);
}


void
Trace(const char* format, ...)
{
	if (!sTraceEnabled)
		return;
	va_list args;
	va_start(args, format);
	LogV(format, args);
	va_end(args);
}


#ifdef _KERNEL_MODE


bigtime_t
SystemTime()
{
	return system_time();
}


int64
RealTimeUsecs()
{
	return real_time_clock_usecs();
}


void
RandomBytes(void* _buffer, size_t length)
{
	uint8* buffer = (uint8*)_buffer;
	while (length > 0) {
		uint32 value = secure_random_value();
		size_t toCopy = length < sizeof(value) ? length : sizeof(value);
		memcpy(buffer, &value, toCopy);
		buffer += toCopy;
		length -= toCopy;
	}
}


void
Snooze(bigtime_t microseconds)
{
	snooze(microseconds);
}


uint32
CurrentUserID()
{
	return geteuid();
}


uint32
CurrentGroupID()
{
	return getegid();
}


int32
CpuCount()
{
	system_info info;
	if (get_system_info(&info) != B_OK || info.cpu_count < 1)
		return 1;
	return (int32)info.cpu_count;
}


Semaphore::Semaphore(const char* name)
	:
	fSemaphore(create_sem(0, name))
{
}


Semaphore::~Semaphore()
{
	if (fSemaphore >= 0)
		delete_sem(fSemaphore);
}


status_t
Semaphore::InitCheck() const
{
	return fSemaphore >= 0 ? B_OK : fSemaphore;
}


void
Semaphore::Acquire()
{
	while (acquire_sem(fSemaphore) == B_INTERRUPTED)
		;
}


void
Semaphore::Release()
{
	release_sem(fSemaphore);
}


Thread::Thread()
	:
	fThread(-1),
	fFunction(NULL),
	fData(NULL)
{
}


Thread::~Thread()
{
	Join();
}


/*static*/ int32
Thread::_Entry(void* data)
{
	Thread* thread = (Thread*)data;
	thread->fFunction(thread->fData);
	return 0;
}


status_t
Thread::Start(const char* name, Function function, void* data)
{
	fFunction = function;
	fData = data;
	fThread = spawn_kernel_thread(&_Entry, name, B_NORMAL_PRIORITY, this);
	if (fThread < 0)
		return fThread;
	resume_thread(fThread);
	return B_OK;
}


void
Thread::Join()
{
	if (fThread < 0)
		return;
	status_t result;
	wait_for_thread(fThread, &result);
	fThread = -1;
}


Mutex::Mutex(const char* name)
{
	mutex_init(&fLock, name);
}


Mutex::~Mutex()
{
	mutex_destroy(&fLock);
}


void
Mutex::Lock()
{
	mutex_lock(&fLock);
}


void
Mutex::Unlock()
{
	mutex_unlock(&fLock);
}


RWLock::RWLock(const char* name)
{
	rw_lock_init(&fLock, name);
}


RWLock::~RWLock()
{
	rw_lock_destroy(&fLock);
}


void
RWLock::ReadLock()
{
	rw_lock_read_lock(&fLock);
}


void
RWLock::ReadUnlock()
{
	rw_lock_read_unlock(&fLock);
}


void
RWLock::WriteLock()
{
	rw_lock_write_lock(&fLock);
}


void
RWLock::WriteUnlock()
{
	rw_lock_write_unlock(&fLock);
}


#else	// !_KERNEL_MODE


bigtime_t
SystemTime()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (bigtime_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}


int64
RealTimeUsecs()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (int64)tv.tv_sec * 1000000 + tv.tv_usec;
}


void
RandomBytes(void* _buffer, size_t length)
{
	uint8* buffer = (uint8*)_buffer;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		size_t done = 0;
		while (done < length) {
			ssize_t got = read(fd, buffer + done, length - done);
			if (got <= 0)
				break;
			done += got;
		}
		close(fd);
		if (done == length)
			return;
	}
	// weak fallback
	static bool seeded = false;
	if (!seeded) {
		srandom((unsigned)(RealTimeUsecs() ^ (intptr_t)&seeded));
		seeded = true;
	}
	for (size_t i = 0; i < length; i++)
		buffer[i] = (uint8)random();
}


void
Snooze(bigtime_t microseconds)
{
	usleep((useconds_t)microseconds);
}


uint32
CurrentUserID()
{
	return geteuid();
}


uint32
CurrentGroupID()
{
	return getegid();
}


int32
CpuCount()
{
	long count = sysconf(_SC_NPROCESSORS_ONLN);
	return count > 0 ? (int32)count : 1;
}


Semaphore::Semaphore(const char* name)
	:
	fCount(0)
{
	(void)name;
	pthread_mutex_init(&fLock, NULL);
	pthread_cond_init(&fCondition, NULL);
}


Semaphore::~Semaphore()
{
	pthread_cond_destroy(&fCondition);
	pthread_mutex_destroy(&fLock);
}


status_t
Semaphore::InitCheck() const
{
	return B_OK;
}


void
Semaphore::Acquire()
{
	pthread_mutex_lock(&fLock);
	while (fCount == 0)
		pthread_cond_wait(&fCondition, &fLock);
	fCount--;
	pthread_mutex_unlock(&fLock);
}


void
Semaphore::Release()
{
	pthread_mutex_lock(&fLock);
	fCount++;
	pthread_cond_signal(&fCondition);
	pthread_mutex_unlock(&fLock);
}


Thread::Thread()
	:
	fStarted(false),
	fFunction(NULL),
	fData(NULL)
{
}


Thread::~Thread()
{
	Join();
}


/*static*/ void*
Thread::_Entry(void* data)
{
	Thread* thread = (Thread*)data;
	thread->fFunction(thread->fData);
	return NULL;
}


status_t
Thread::Start(const char* name, Function function, void* data)
{
	(void)name;
	fFunction = function;
	fData = data;
	if (pthread_create(&fThread, NULL, &_Entry, this) != 0)
		return B_NO_MEMORY;
	fStarted = true;
	return B_OK;
}


void
Thread::Join()
{
	if (!fStarted)
		return;
	pthread_join(fThread, NULL);
	fStarted = false;
}


Mutex::Mutex(const char* name)
{
	(void)name;
	pthread_mutex_init(&fLock, NULL);
}


Mutex::~Mutex()
{
	pthread_mutex_destroy(&fLock);
}


void
Mutex::Lock()
{
	pthread_mutex_lock(&fLock);
}


void
Mutex::Unlock()
{
	pthread_mutex_unlock(&fLock);
}


RWLock::RWLock(const char* name)
{
	(void)name;
	pthread_rwlock_init(&fLock, NULL);
}


RWLock::~RWLock()
{
	pthread_rwlock_destroy(&fLock);
}


void
RWLock::ReadLock()
{
	pthread_rwlock_rdlock(&fLock);
}


void
RWLock::ReadUnlock()
{
	pthread_rwlock_unlock(&fLock);
}


void
RWLock::WriteLock()
{
	pthread_rwlock_wrlock(&fLock);
}


void
RWLock::WriteUnlock()
{
	pthread_rwlock_unlock(&fLock);
}


#endif	// !_KERNEL_MODE


}	// namespace smb2
