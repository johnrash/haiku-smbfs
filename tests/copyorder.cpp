/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * copyorder - copies one file the way Tracker's CopyFile() does: write the
 * data, then set permissions, owner, group, modification and creation time
 * on the still-open destination, then close it. vm-test.sh uses it to check
 * that smbfs keeps the data and times of copied read-only files.
 *
 * usage: copyorder <source> <destination>
 * build: g++ -o copyorder copyorder.cpp -lbe
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <File.h>


int
main(int argc, char** argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: copyorder <source> <destination>\n");
		return 2;
	}

	BFile source(argv[1], B_READ_ONLY);
	struct stat st;
	if (source.InitCheck() != B_OK || source.GetStat(&st) != B_OK) {
		fprintf(stderr, "copyorder: cannot read %s\n", argv[1]);
		return 1;
	}
	BFile destination(argv[2], O_RDWR | O_CREAT);
	status_t status = destination.InitCheck();
	if (status != B_OK) {
		fprintf(stderr, "copyorder: cannot create %s: %s\n", argv[2],
			strerror(status));
		return 1;
	}

	char buffer[65536];
	ssize_t bytes;
	while ((bytes = source.Read(buffer, sizeof(buffer))) > 0) {
		if (destination.Write(buffer, bytes) != bytes) {
			fprintf(stderr, "copyorder: writing %s failed\n", argv[2]);
			return 1;
		}
	}
	if (bytes < 0) {
		fprintf(stderr, "copyorder: reading %s failed\n", argv[1]);
		return 1;
	}

	// Tracker's order, on the still-open file
	destination.SetPermissions(st.st_mode);
	destination.SetOwner(st.st_uid);
	destination.SetGroup(st.st_gid);
	destination.SetModificationTime(st.st_mtime);
	destination.SetCreationTime(st.st_crtime);
	return 0;
}
