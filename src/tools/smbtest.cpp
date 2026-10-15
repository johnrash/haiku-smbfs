/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Userland test harness for the SMB2 protocol core. Builds on Linux and on
 * Haiku, and exercises the same code that the kernel add-on uses.
 */


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../smb2/Connection.h"
#include "../smb2/NtStatus.h"
#include "../smb2/Platform.h"
#include "../smb2/Utf.h"

using namespace smb2;


static const char*
status_string(status_t status)
{
	switch (status) {
		case B_OK: return "B_OK";
		case B_ERROR: return "B_ERROR";
		case B_NO_MEMORY: return "B_NO_MEMORY";
		case B_IO_ERROR: return "B_IO_ERROR";
		case B_PERMISSION_DENIED: return "B_PERMISSION_DENIED";
		case B_BAD_VALUE: return "B_BAD_VALUE";
		case B_NAME_NOT_FOUND: return "B_NAME_NOT_FOUND";
		case B_TIMED_OUT: return "B_TIMED_OUT";
		case B_BUSY: return "B_BUSY";
		case B_BAD_DATA: return "B_BAD_DATA";
		case B_NOT_SUPPORTED: return "B_NOT_SUPPORTED";
		case B_FILE_ERROR: return "B_FILE_ERROR";
		case B_FILE_EXISTS: return "B_FILE_EXISTS";
		case B_ENTRY_NOT_FOUND: return "B_ENTRY_NOT_FOUND";
		case B_NAME_TOO_LONG: return "B_NAME_TOO_LONG";
		case B_NOT_A_DIRECTORY: return "B_NOT_A_DIRECTORY";
		case B_DIRECTORY_NOT_EMPTY: return "B_DIRECTORY_NOT_EMPTY";
		case B_DEVICE_FULL: return "B_DEVICE_FULL";
		case B_READ_ONLY_DEVICE: return "B_READ_ONLY_DEVICE";
		case B_IS_A_DIRECTORY: return "B_IS_A_DIRECTORY";
		case SMB2_DISCONNECTED: return "SMB2_DISCONNECTED";
		default: {
			static char buffer[32];
			snprintf(buffer, sizeof(buffer), "0x%08x", (unsigned)status);
			return buffer;
		}
	}
}


static int sFailures = 0;
static int sChecks = 0;


#define CHECK(condition, ...) \
	do { \
		sChecks++; \
		if (!(condition)) { \
			sFailures++; \
			printf("FAIL %s:%d: ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	} while (0)

#define CHECK_STATUS(status, expected, what) \
	CHECK((status) == (expected), "%s: got %s, expected %s", what, \
		status_string(status), status_string(expected))


static void
print_time(uint64 fileTime)
{
	struct timespec spec;
	FileTimeToTimespec(fileTime, spec);
	struct tm tm;
	localtime_r(&spec.tv_sec, &tm);
	char buffer[64];
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
	printf("%s", buffer);
}


static status_t
list_directory(Connection& connection, const char* path, bool verbose,
	int* _count)
{
	FileId id;
	status_t status = connection.Create(path, FILE_LIST_DIRECTORY
		| FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, FILE_OPEN, FILE_DIRECTORY_FILE,
		0, id);
	if (status != B_OK)
		return status;

	uint8* buffer = (uint8*)malloc(65536);
	int count = 0;
	bool first = true;
	while (true) {
		size_t length;
		status = connection.QueryDirectory(id, "*",
			first ? SMB2_RESTART_SCANS : 0, buffer, 65536, &length);
		first = false;
		if (status == B_ENTRY_NOT_FOUND) {
			status = B_OK;
			break;
		}
		if (status != B_OK)
			break;

		DirectoryIterator iterator(buffer, length);
		const uint8* nameUtf16;
		size_t nameLength;
		FileInfo info;
		while (iterator.Next(&nameUtf16, &nameLength, info)) {
			char name[1024];
			Utf16LEToUtf8(nameUtf16, nameLength, name, sizeof(name));
			count++;
			if (verbose) {
				printf("%c%c %12llu  ", info.IsDirectory() ? 'd' : '-',
					info.IsReadOnly() ? 'r' : 'w',
					(unsigned long long)info.endOfFile);
				print_time(info.lastWriteTime);
				printf("  %s\n", name);
			}
		}
	}
	free(buffer);
	connection.Close(id);
	if (_count != NULL)
		*_count = count;
	return status;
}


static status_t
read_file(Connection& connection, const char* path, uint8** _data,
	size_t* _length)
{
	FileId id;
	FileInfo info;
	status_t status = connection.Create(path, FILE_READ_DATA
		| FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE, 0, id, &info);
	if (status != B_OK)
		return status;

	size_t size = (size_t)info.endOfFile;
	uint8* data = (uint8*)malloc(size + 1);
	size_t total = 0;
	while (total < size) {
		size_t bytesRead = 0;
		status = connection.Read(id, total, data + total, size - total,
			&bytesRead);
		if (status != B_OK || bytesRead == 0)
			break;
		total += bytesRead;
	}
	connection.Close(id);
	if (status != B_OK) {
		free(data);
		return status;
	}
	*_data = data;
	*_length = total;
	return B_OK;
}


static status_t
write_file(Connection& connection, const char* path, const uint8* data,
	size_t length, bool truncate)
{
	FileId id;
	status_t status = connection.Create(path, FILE_WRITE_DATA
		| FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, FILE_SHARE_ALL,
		truncate ? FILE_OVERWRITE_IF : FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE,
		FILE_ATTRIBUTE_NORMAL, id);
	if (status != B_OK)
		return status;
	size_t total = 0;
	while (total < length) {
		size_t written = 0;
		status = connection.Write(id, total, data + total, length - total,
			&written);
		if (status != B_OK || written == 0)
			break;
		total += written;
	}
	status_t closeStatus = connection.Close(id);
	if (status == B_OK)
		status = closeStatus;
	if (status == B_OK && total != length)
		status = B_IO_ERROR;
	return status;
}


static void
fill_pattern(uint8* buffer, size_t length, uint32 seed)
{
	uint32 x = seed;
	for (size_t i = 0; i < length; i++) {
		x = x * 1103515245 + 12345;
		buffer[i] = (uint8)(x >> 16);
	}
}


static bool
local_file_equals(const char* localRoot, const char* relativePath,
	const uint8* data, size_t length)
{
	if (localRoot == NULL)
		return true;
	char path[2048];
	snprintf(path, sizeof(path), "%s/%s", localRoot, relativePath);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("  (local open of %s failed: %s)\n", path, strerror(errno));
		return false;
	}
	uint8* local = (uint8*)malloc(length + 1);
	ssize_t got = read(fd, local, length + 1);
	close(fd);
	bool equal = got == (ssize_t)length && memcmp(local, data, length) == 0;
	free(local);
	return equal;
}


static int
selftest(Connection& connection, const char* localRoot)
{
	char base[128];
	snprintf(base, sizeof(base), "smbtest-%d", (int)getpid());
	char path[1024], path2[1024];
	status_t status;

	printf("== selftest in %s ==\n", base);

	// directory creation
	FileInfo info;
	status = connection.CreateDirectoryPath(base, &info);
	CHECK_STATUS(status, B_OK, "mkdir base");
	CHECK(info.IsDirectory(), "mkdir base: not a directory");
	status = connection.CreateDirectoryPath(base, NULL);
	CHECK_STATUS(status, B_FILE_EXISTS, "mkdir existing");

	// stat of directory
	status = connection.QueryPathInfo(base, info);
	CHECK_STATUS(status, B_OK, "stat base");
	CHECK(info.IsDirectory(), "stat base: not a directory");

	// nonexistent
	snprintf(path, sizeof(path), "%s/does-not-exist", base);
	status = connection.QueryPathInfo(path, info);
	CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "stat nonexistent");
	snprintf(path, sizeof(path), "%s/nodir/file", base);
	status = connection.QueryPathInfo(path, info);
	CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "stat nonexistent path");

	// files of various sizes
	static const size_t kSizes[] = {0, 1, 4095, 4096, 65535, 65536, 65537,
		1024 * 1024 + 123, 3 * 1024 * 1024 + 7};
	for (size_t i = 0; i < sizeof(kSizes) / sizeof(kSizes[0]); i++) {
		size_t size = kSizes[i];
		snprintf(path, sizeof(path), "%s/file-%lu.bin", base,
			(unsigned long)size);
		uint8* data = (uint8*)malloc(size + 1);
		fill_pattern(data, size, (uint32)size + 1);
		status = write_file(connection, path, data, size, true);
		CHECK_STATUS(status, B_OK, "write file");
		status = connection.QueryPathInfo(path, info);
		CHECK_STATUS(status, B_OK, "stat file");
		CHECK(info.endOfFile == size, "size mismatch for %s: %llu", path,
			(unsigned long long)info.endOfFile);
		CHECK(!info.IsDirectory(), "file reported as directory");
		uint8* readBack = NULL;
		size_t readLength = 0;
		status = read_file(connection, path, &readBack, &readLength);
		CHECK_STATUS(status, B_OK, "read file");
		if (status == B_OK) {
			CHECK(readLength == size && memcmp(readBack, data, size) == 0,
				"content mismatch for %s (read %lu)", path,
				(unsigned long)readLength);
			free(readBack);
		}
		CHECK(local_file_equals(localRoot, path, data, size),
			"local content mismatch for %s", path);
		free(data);
	}

	// partial reads / reads past EOF
	{
		snprintf(path, sizeof(path), "%s/file-65537.bin", base);
		FileId id;
		status = connection.Create(path, FILE_READ_DATA, FILE_SHARE_ALL,
			FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0, id);
		CHECK_STATUS(status, B_OK, "open for partial read");
		if (status == B_OK) {
			uint8 buffer[100];
			size_t bytesRead = 99;
			status = connection.Read(id, 65537, buffer, 100, &bytesRead);
			CHECK_STATUS(status, B_OK, "read at EOF");
			CHECK(bytesRead == 0, "read at EOF returned %lu bytes",
				(unsigned long)bytesRead);
			status = connection.Read(id, 65530, buffer, 100, &bytesRead);
			CHECK_STATUS(status, B_OK, "read across EOF");
			CHECK(bytesRead == 7, "read across EOF returned %lu bytes",
				(unsigned long)bytesRead);
			uint8 expected[65537];
			fill_pattern(expected, 65537, 65537 + 1);
			CHECK(memcmp(buffer, expected + 65530, 7) == 0,
				"read across EOF content mismatch");
			connection.Close(id);
		}
	}

	// overwrite in the middle and append
	{
		snprintf(path, sizeof(path), "%s/file-4096.bin", base);
		FileId id;
		status = connection.Create(path, FILE_WRITE_DATA | FILE_READ_DATA,
			FILE_SHARE_ALL, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0, id);
		CHECK_STATUS(status, B_OK, "open for rewrite");
		if (status == B_OK) {
			size_t written;
			status = connection.Write(id, 100, "HELLO", 5, &written);
			CHECK_STATUS(status, B_OK, "write middle");
			status = connection.Write(id, 4096, "TAIL", 4, &written);
			CHECK_STATUS(status, B_OK, "write append");
			connection.Close(id);
			uint8* data; size_t length;
			status = read_file(connection, path, &data, &length);
			CHECK_STATUS(status, B_OK, "read rewritten");
			if (status == B_OK) {
				CHECK(length == 4100, "rewritten length %lu",
					(unsigned long)length);
				CHECK(memcmp(data + 100, "HELLO", 5) == 0, "middle write lost");
				CHECK(memcmp(data + 4096, "TAIL", 4) == 0, "append lost");
				free(data);
			}
		}
	}

	// truncate via SetEndOfFile
	{
		snprintf(path, sizeof(path), "%s/file-4096.bin", base);
		status = connection.SetPathEndOfFile(path, 50);
		CHECK_STATUS(status, B_OK, "set end of file");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.endOfFile == 50, "truncate size %llu",
			(unsigned long long)info.endOfFile);
		status = connection.SetPathEndOfFile(path, 8000);
		CHECK_STATUS(status, B_OK, "extend file");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.endOfFile == 8000, "extend size %llu",
			(unsigned long long)info.endOfFile);
	}

	// set times
	{
		snprintf(path, sizeof(path), "%s/file-1.bin", base);
		struct timespec spec;
		spec.tv_sec = 1000000000;
		spec.tv_nsec = 0;
		uint64 fileTime = TimespecToFileTime(spec);
		status = connection.SetPathBasicInfo(path, 0, 0, fileTime, 0, 0);
		CHECK_STATUS(status, B_OK, "set mtime");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.lastWriteTime == fileTime,
			"mtime mismatch: %llu vs %llu",
			(unsigned long long)info.lastWriteTime,
			(unsigned long long)fileTime);
		// read-only attribute
		status = connection.SetPathBasicInfo(path, 0, 0, 0, 0,
			FILE_ATTRIBUTE_READONLY);
		CHECK_STATUS(status, B_OK, "set read-only");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.IsReadOnly(), "read-only not set");
		status = connection.SetPathBasicInfo(path, 0, 0, 0, 0,
			FILE_ATTRIBUTE_NORMAL);
		CHECK_STATUS(status, B_OK, "clear read-only");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && !info.IsReadOnly(), "read-only not cleared");
	}

	// rename
	{
		snprintf(path, sizeof(path), "%s/file-1.bin", base);
		snprintf(path2, sizeof(path2), "%s/renamed.bin", base);
		status = connection.RenamePath(path, path2, false);
		CHECK_STATUS(status, B_OK, "rename");
		status = connection.QueryPathInfo(path, info);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "stat old name");
		status = connection.QueryPathInfo(path2, info);
		CHECK_STATUS(status, B_OK, "stat new name");
		// rename over existing with replace
		snprintf(path, sizeof(path), "%s/file-0.bin", base);
		status = connection.RenamePath(path2, path, true);
		CHECK_STATUS(status, B_OK, "rename replace");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.endOfFile == 1, "replaced size %llu",
			(unsigned long long)info.endOfFile);
		// rename into subdirectory
		snprintf(path2, sizeof(path2), "%s/subdir", base);
		status = connection.CreateDirectoryPath(path2, NULL);
		CHECK_STATUS(status, B_OK, "mkdir subdir");
		snprintf(path2, sizeof(path2), "%s/subdir/moved.bin", base);
		status = connection.RenamePath(path, path2, false);
		CHECK_STATUS(status, B_OK, "rename into subdir");
		status = connection.QueryPathInfo(path2, info);
		CHECK_STATUS(status, B_OK, "stat moved");
		// rename directory
		snprintf(path, sizeof(path), "%s/subdir", base);
		snprintf(path2, sizeof(path2), "%s/subdir2", base);
		status = connection.RenamePath(path, path2, false);
		CHECK_STATUS(status, B_OK, "rename directory");
		snprintf(path2, sizeof(path2), "%s/subdir2/moved.bin", base);
		status = connection.QueryPathInfo(path2, info);
		CHECK_STATUS(status, B_OK, "stat inside renamed directory");
	}

	// unicode names
	{
		snprintf(path, sizeof(path), "%s/Übung-файл-日本語.txt", base);
		status = write_file(connection, path, (const uint8*)"unicode", 7, true);
		CHECK_STATUS(status, B_OK, "write unicode name");
		status = connection.QueryPathInfo(path, info);
		CHECK(status == B_OK && info.endOfFile == 7, "stat unicode name");
		int count = 0;
		status = list_directory(connection, base, false, &count);
		CHECK_STATUS(status, B_OK, "list base");
	}

	// directory listing with many entries
	{
		snprintf(path, sizeof(path), "%s/many", base);
		status = connection.CreateDirectoryPath(path, NULL);
		CHECK_STATUS(status, B_OK, "mkdir many");
		const int kCount = 300;
		for (int i = 0; i < kCount; i++) {
			snprintf(path, sizeof(path), "%s/many/entry-%03d.txt", base, i);
			status = write_file(connection, path, (const uint8*)"x", 1, true);
			if (status != B_OK) {
				CHECK_STATUS(status, B_OK, "create many entry");
				break;
			}
		}
		snprintf(path, sizeof(path), "%s/many", base);
		int count = 0;
		status = list_directory(connection, path, false, &count);
		CHECK_STATUS(status, B_OK, "list many");
		CHECK(count == kCount + 2, "listed %d entries, expected %d", count,
			kCount + 2);
		// rmdir non-empty must fail
		status = connection.DeletePath(path, true);
		CHECK_STATUS(status, B_DIRECTORY_NOT_EMPTY, "rmdir non-empty");
		for (int i = 0; i < kCount; i++) {
			snprintf(path, sizeof(path), "%s/many/entry-%03d.txt", base, i);
			status = connection.DeletePath(path, false);
			if (status != B_OK) {
				CHECK_STATUS(status, B_OK, "delete many entry");
				break;
			}
		}
		snprintf(path, sizeof(path), "%s/many", base);
		status = connection.DeletePath(path, true);
		CHECK_STATUS(status, B_OK, "rmdir many");
	}

	// delete file / errors
	{
		snprintf(path, sizeof(path), "%s/file-4096.bin", base);
		status = connection.DeletePath(path, false);
		CHECK_STATUS(status, B_OK, "delete file");
		status = connection.DeletePath(path, false);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "delete nonexistent");
		snprintf(path, sizeof(path), "%s/subdir2", base);
		status = connection.DeletePath(path, false);
		CHECK(status == B_IS_A_DIRECTORY || status == B_ENTRY_NOT_FOUND
			|| status == B_PERMISSION_DENIED || status == B_BAD_VALUE,
			"unlink directory returned %s", status_string(status));
		snprintf(path, sizeof(path), "%s/file-4095.bin", base);
		status = connection.DeletePath(path, true);
		CHECK(status == B_NOT_A_DIRECTORY || status == B_ENTRY_NOT_FOUND
			|| status == B_BAD_VALUE,
			"rmdir file returned %s", status_string(status));
	}

	// filesystem info
	{
		FsInfo fsInfo;
		status = connection.QueryFsInfo(fsInfo);
		CHECK_STATUS(status, B_OK, "fs info");
		CHECK(fsInfo.totalUnits > 0 && fsInfo.bytesPerSector > 0,
			"fs info values");
		printf("fs: %s, %llu total units, %llu free, %u bytes/sector, "
			"%u sectors/unit, max name %u\n", fsInfo.fsName,
			(unsigned long long)fsInfo.totalUnits,
			(unsigned long long)fsInfo.availableUnits, fsInfo.bytesPerSector,
			fsInfo.sectorsPerUnit, fsInfo.maxComponentLength);
	}

	// echo
	status = connection.Echo();
	CHECK_STATUS(status, B_OK, "echo");

	// cleanup: remove everything that remains
	{
		const char* remaining[] = {"file-4095.bin", "file-65535.bin",
			"file-65536.bin", "file-65537.bin", "file-1048699.bin",
			"file-3145735.bin", "Übung-файл-日本語.txt",
			"subdir2/moved.bin", "subdir2", NULL};
		for (int i = 0; remaining[i] != NULL; i++) {
			snprintf(path, sizeof(path), "%s/%s", base, remaining[i]);
			bool directory = strcmp(remaining[i], "subdir2") == 0;
			status = connection.DeletePath(path, directory);
			CHECK_STATUS(status, B_OK, remaining[i]);
		}
		status = connection.DeletePath(base, true);
		CHECK_STATUS(status, B_OK, "rmdir base");
		status = connection.QueryPathInfo(base, info);
		CHECK_STATUS(status, B_ENTRY_NOT_FOUND, "base removed");
	}

	printf("== %d checks, %d failures ==\n", sChecks, sFailures);
	return sFailures == 0 ? 0 : 1;
}


static int
benchmark(Connection& connection, const char* path)
{
	FileId id;
	FileInfo info;
	status_t status = connection.Create(path, FILE_READ_DATA
		| FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE, 0, id, &info);
	if (status != B_OK) {
		printf("open failed: %s\n", status_string(status));
		return 1;
	}
	size_t chunk = 1024 * 1024;
	uint8* buffer = (uint8*)malloc(chunk);
	bigtime_t start = SystemTime();
	uint64 total = 0;
	while (total < info.endOfFile) {
		size_t bytesRead;
		status = connection.Read(id, total, buffer, chunk, &bytesRead);
		if (status != B_OK || bytesRead == 0)
			break;
		total += bytesRead;
	}
	bigtime_t elapsed = SystemTime() - start;
	connection.Close(id);
	free(buffer);
	printf("read %llu bytes in %.3f s: %.1f MB/s\n",
		(unsigned long long)total, elapsed / 1000000.0,
		elapsed > 0 ? total / (elapsed / 1000000.0) / 1048576.0 : 0.0);
	return 0;
}


static void
usage()
{
	fprintf(stderr,
		"usage: smbtest [options] <command> [args]\n"
		"options:\n"
		"  -s <server>      server host name or address\n"
		"  -S <share>       share name\n"
		"  -u <user>        user name (empty for anonymous)\n"
		"  -p <password>    password\n"
		"  -d <domain>      domain\n"
		"  -P <port>        TCP port (default 445)\n"
		"  --sign           require signing\n"
		"  --seal           require encryption\n"
		"  --max-dialect X  highest dialect to offer (e.g. 0x0302)\n"
		"  --min-dialect X  lowest dialect to offer\n"
		"  --local-root D   local directory that mirrors the share (selftest)\n"
		"  --trace          enable protocol tracing\n"
		"commands:\n"
		"  info                 show connection information\n"
		"  ls [path]            list a directory\n"
		"  stat <path>          show file information\n"
		"  cat <path>           print file contents\n"
		"  get <path> <local>   download a file\n"
		"  put <local> <path>   upload a file\n"
		"  mkdir <path>         create a directory\n"
		"  rm <path>            delete a file\n"
		"  rmdir <path>         delete a directory\n"
		"  mv <from> <to>       rename\n"
		"  df                   show file system information\n"
		"  bench <path>         measure read throughput\n"
		"  selftest             run the built-in test suite\n");
}


int
main(int argc, char** argv)
{
	const char* server = getenv("SMB_SERVER");
	const char* share = getenv("SMB_SHARE");
	const char* user = getenv("SMB_USER");
	const char* password = getenv("SMB_PASSWORD");
	const char* domain = getenv("SMB_DOMAIN");
	const char* localRoot = NULL;
	Options options;

	int i = 1;
	for (; i < argc; i++) {
		const char* arg = argv[i];
		if (arg[0] != '-')
			break;
		if (strcmp(arg, "-s") == 0 && i + 1 < argc)
			server = argv[++i];
		else if (strcmp(arg, "-S") == 0 && i + 1 < argc)
			share = argv[++i];
		else if (strcmp(arg, "-u") == 0 && i + 1 < argc)
			user = argv[++i];
		else if (strcmp(arg, "-p") == 0 && i + 1 < argc)
			password = argv[++i];
		else if (strcmp(arg, "-d") == 0 && i + 1 < argc)
			domain = argv[++i];
		else if (strcmp(arg, "-P") == 0 && i + 1 < argc)
			setenv("SMB_PORT", argv[++i], 1);
		else if (strcmp(arg, "--sign") == 0)
			options.sign = true;
		else if (strcmp(arg, "--seal") == 0)
			options.seal = true;
		else if (strcmp(arg, "--max-dialect") == 0 && i + 1 < argc)
			options.maxDialect = (uint16)strtoul(argv[++i], NULL, 0);
		else if (strcmp(arg, "--min-dialect") == 0 && i + 1 < argc)
			options.minDialect = (uint16)strtoul(argv[++i], NULL, 0);
		else if (strcmp(arg, "--local-root") == 0 && i + 1 < argc)
			localRoot = argv[++i];
		else if (strcmp(arg, "--trace") == 0)
			SetTraceEnabled(true);
		else {
			usage();
			return 1;
		}
	}
	if (i >= argc || server == NULL || share == NULL) {
		usage();
		return 1;
	}
	const char* command = argv[i++];
	uint16 port = getenv("SMB_PORT") != NULL
		? (uint16)atoi(getenv("SMB_PORT")) : 445;

	Credentials credentials;
	credentials.user = user;
	credentials.password = password;
	credentials.domain = domain;
	credentials.workstation = "SMBTEST";

	Connection connection;
	status_t status = connection.Init(server, port, share, credentials,
		options);
	if (status == B_OK)
		status = connection.Connect();
	if (status != B_OK) {
		printf("connection failed: %s\n", status_string(status));
		return 1;
	}

	if (strcmp(command, "info") == 0) {
		printf("server: %s (%s)\nshare: %s\ndialect: 0x%04x\n"
			"signing: %s\nencryption: %s\nsession flags: 0x%x\n"
			"share flags: 0x%08x\nmaximal access: 0x%08x\n"
			"max read: %u\nmax write: %u\nmax transact: %u\n",
			connection.Host(), connection.ServerName(), connection.Share(),
			connection.Dialect(), connection.IsSigning() ? "yes" : "no",
			connection.IsEncrypting() ? "yes" : "no",
			connection.SessionFlags(), connection.ShareFlags(),
			connection.MaximalAccess(), connection.MaxReadSize(),
			connection.MaxWriteSize(), connection.MaxTransactSize());
		return 0;
	}
	if (strcmp(command, "ls") == 0) {
		const char* path = i < argc ? argv[i] : "";
		int count;
		status = list_directory(connection, path, true, &count);
		if (status != B_OK)
			printf("ls failed: %s\n", status_string(status));
		return status == B_OK ? 0 : 1;
	}
	if (strcmp(command, "stat") == 0 && i < argc) {
		FileInfo info;
		status = connection.QueryPathInfo(argv[i], info);
		if (status != B_OK) {
			printf("stat failed: %s\n", status_string(status));
			return 1;
		}
		printf("%s: %s, size %llu, alloc %llu, attributes 0x%08x, links %u, "
			"index %llu\n  created ", argv[i],
			info.IsDirectory() ? "directory" : "file",
			(unsigned long long)info.endOfFile,
			(unsigned long long)info.allocationSize, info.attributes,
			info.numberOfLinks, (unsigned long long)info.indexNumber);
		print_time(info.creationTime);
		printf("\n  modified ");
		print_time(info.lastWriteTime);
		printf("\n  changed ");
		print_time(info.changeTime);
		printf("\n  accessed ");
		print_time(info.lastAccessTime);
		printf("\n");
		return 0;
	}
	if (strcmp(command, "cat") == 0 && i < argc) {
		uint8* data; size_t length;
		status = read_file(connection, argv[i], &data, &length);
		if (status != B_OK) {
			printf("read failed: %s\n", status_string(status));
			return 1;
		}
		fwrite(data, 1, length, stdout);
		free(data);
		return 0;
	}
	if (strcmp(command, "get") == 0 && i + 1 < argc) {
		uint8* data; size_t length;
		status = read_file(connection, argv[i], &data, &length);
		if (status != B_OK) {
			printf("read failed: %s\n", status_string(status));
			return 1;
		}
		FILE* file = fopen(argv[i + 1], "wb");
		if (file == NULL) {
			printf("cannot open %s\n", argv[i + 1]);
			return 1;
		}
		fwrite(data, 1, length, file);
		fclose(file);
		free(data);
		printf("%lu bytes\n", (unsigned long)length);
		return 0;
	}
	if (strcmp(command, "put") == 0 && i + 1 < argc) {
		FILE* file = fopen(argv[i], "rb");
		if (file == NULL) {
			printf("cannot open %s\n", argv[i]);
			return 1;
		}
		fseek(file, 0, SEEK_END);
		long size = ftell(file);
		fseek(file, 0, SEEK_SET);
		uint8* data = (uint8*)malloc(size + 1);
		if (fread(data, 1, size, file) != (size_t)size) {
			printf("short read\n");
			return 1;
		}
		fclose(file);
		status = write_file(connection, argv[i + 1], data, size, true);
		free(data);
		if (status != B_OK) {
			printf("write failed: %s\n", status_string(status));
			return 1;
		}
		printf("%ld bytes\n", size);
		return 0;
	}
	if (strcmp(command, "mkdir") == 0 && i < argc) {
		status = connection.CreateDirectoryPath(argv[i], NULL);
		if (status != B_OK)
			printf("mkdir failed: %s\n", status_string(status));
		return status == B_OK ? 0 : 1;
	}
	if (strcmp(command, "rm") == 0 && i < argc) {
		status = connection.DeletePath(argv[i], false);
		if (status != B_OK)
			printf("rm failed: %s\n", status_string(status));
		return status == B_OK ? 0 : 1;
	}
	if (strcmp(command, "rmdir") == 0 && i < argc) {
		status = connection.DeletePath(argv[i], true);
		if (status != B_OK)
			printf("rmdir failed: %s\n", status_string(status));
		return status == B_OK ? 0 : 1;
	}
	if (strcmp(command, "mv") == 0 && i + 1 < argc) {
		status = connection.RenamePath(argv[i], argv[i + 1], true);
		if (status != B_OK)
			printf("mv failed: %s\n", status_string(status));
		return status == B_OK ? 0 : 1;
	}
	if (strcmp(command, "df") == 0) {
		FsInfo info;
		status = connection.QueryFsInfo(info);
		if (status != B_OK) {
			printf("df failed: %s\n", status_string(status));
			return 1;
		}
		uint64 unit = (uint64)info.sectorsPerUnit * info.bytesPerSector;
		printf("%s: total %llu MB, free %llu MB (unit %llu bytes), "
			"max name %u, attributes 0x%08x\n", info.fsName,
			(unsigned long long)(info.totalUnits * unit / 1048576),
			(unsigned long long)(info.availableUnits * unit / 1048576),
			(unsigned long long)unit, info.maxComponentLength,
			info.attributes);
		return 0;
	}
	if (strcmp(command, "bench") == 0 && i < argc)
		return benchmark(connection, argv[i]);
	if (strcmp(command, "selftest") == 0)
		return selftest(connection, localRoot);

	usage();
	return 1;
}
