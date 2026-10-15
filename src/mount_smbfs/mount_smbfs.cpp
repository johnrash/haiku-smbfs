/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * mount_smbfs - mounts an SMB share using the smbfs kernel add-on.
 */


#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <fs_volume.h>
#include <String.h>


static void
usage(FILE* out)
{
	fprintf(out,
		"Usage: mount_smbfs [options] //server/share [mountpoint]\n"
		"Mounts an SMB2/SMB3 network share.\n"
		"\n"
		"Options:\n"
		"  -u, --user <name>        user name (default: guest/anonymous)\n"
		"  -p, --password <pass>    password (prompted if omitted)\n"
		"  -d, --domain <domain>    domain or workgroup\n"
		"  -r, --read-only          mount read-only\n"
		"  -s, --sign               require message signing\n"
		"  -e, --encrypt            require encryption (SMB 3.x)\n"
		"  -P, --port <port>        TCP port (default 445)\n"
		"  -o, --options <list>     additional smbfs mount options, separated\n"
		"                           by spaces (e.g. \"vers=3.0 cache=5\")\n"
		"  -n, --no-prompt          never ask for a password\n"
		"  -h, --help               show this help\n"
		"\n"
		"The mount point defaults to /<share> (with a number appended if that\n"
		"name is taken) and is created if it does not exist. Mount points must\n"
		"be empty directories. Use \"unmount <mountpoint>\" to unmount.\n");
}


static bool
read_password(const char* prompt, char* buffer, size_t size)
{
	if (!isatty(STDIN_FILENO))
		return fgets(buffer, size, stdin) != NULL;

	fputs(prompt, stderr);
	fflush(stderr);

	struct termios oldAttributes, newAttributes;
	bool restore = tcgetattr(STDIN_FILENO, &oldAttributes) == 0;
	if (restore) {
		newAttributes = oldAttributes;
		newAttributes.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &newAttributes);
	}
	bool result = fgets(buffer, size, stdin) != NULL;
	if (restore)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldAttributes);
	fputs("\n", stderr);
	return result;
}



// Mount point policy (shared with SMBMounter): never mount over system
// directories or non-empty directories. Like Haiku's disk mounter, the default
// mount point is /<share>, with a number appended if that is taken.
static const char* const kReservedMountPoints[] = {
	"/", "/boot", "/dev", "/bin", "/etc", "/packages", "/system", "/tmp",
	"/var", "/trash", NULL
};


static bool
is_reserved_mount_point(const char* path)
{
	BString normalized(path);
	while (normalized.Length() > 1 && normalized.EndsWith("/"))
		normalized.Truncate(normalized.Length() - 1);
	for (int i = 0; kReservedMountPoints[i] != NULL; i++) {
		if (normalized == kReservedMountPoints[i])
			return true;
	}
	return false;
}


// Returns B_OK if the path can be used as a mount point (it either does not
// exist, or is an empty directory); *_exists tells whether it exists.
static status_t
check_mount_point(const char* path, bool* _exists)
{
	if (is_reserved_mount_point(path))
		return B_NOT_ALLOWED;
	struct stat st;
	if (lstat(path, &st) != 0) {
		*_exists = false;
		return B_OK;
	}
	*_exists = true;
	if (!S_ISDIR(st.st_mode))
		return B_NOT_A_DIRECTORY;
	DIR* dir = opendir(path);
	if (dir == NULL)
		return errno;
	bool empty = true;
	while (struct dirent* entry = readdir(dir)) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
			empty = false;
			break;
		}
	}
	closedir(dir);
	return empty ? B_OK : B_DIRECTORY_NOT_EMPTY;
}


static BString
default_mount_point(const char* share)
{
	BString name(share);
	name.ReplaceAll('/', '-');
	name.ReplaceAll('\\', '-');
	name.Trim();
	if (name.Length() == 0)
		name = "smb";
	for (int32 i = 1; i < 1000; i++) {
		BString path("/");
		path << name;
		if (i > 1)
			path << (i - 1);
		bool exists;
		if (check_mount_point(path.String(), &exists) == B_OK)
			return path;
	}
	BString path("/");
	path << name;
	return path;
}


static void
append_option(BString& parameters, const char* key, const char* value)
{
	if (value == NULL || value[0] == '\0')
		return;
	parameters << ' ' << key << '=';
	// quote values containing spaces or quotes
	if (strpbrk(value, " \t\"'") != NULL) {
		parameters << '"';
		for (const char* p = value; *p != '\0'; p++) {
			if (*p == '"' || *p == '\\')
				parameters << '\\';
			parameters << *p;
		}
		parameters << '"';
	} else
		parameters << value;
}


int
main(int argc, char** argv)
{
	const char* user = NULL;
	const char* password = NULL;
	const char* domain = NULL;
	const char* port = NULL;
	const char* extraOptions = NULL;
	bool readOnly = false;
	bool sign = false;
	bool seal = false;
	bool noPrompt = false;

	static struct option kLongOptions[] = {
		{"user", required_argument, NULL, 'u'},
		{"password", required_argument, NULL, 'p'},
		{"domain", required_argument, NULL, 'd'},
		{"read-only", no_argument, NULL, 'r'},
		{"sign", no_argument, NULL, 's'},
		{"encrypt", no_argument, NULL, 'e'},
		{"port", required_argument, NULL, 'P'},
		{"options", required_argument, NULL, 'o'},
		{"no-prompt", no_argument, NULL, 'n'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	int c;
	while ((c = getopt_long(argc, argv, "u:p:d:rseP:o:nh", kLongOptions,
			NULL)) != -1) {
		switch (c) {
			case 'u': user = optarg; break;
			case 'p': password = optarg; break;
			case 'd': domain = optarg; break;
			case 'r': readOnly = true; break;
			case 's': sign = true; break;
			case 'e': seal = true; break;
			case 'P': port = optarg; break;
			case 'o': extraOptions = optarg; break;
			case 'n': noPrompt = true; break;
			case 'h': usage(stdout); return 0;
			default: usage(stderr); return 1;
		}
	}

	if (optind >= argc) {
		usage(stderr);
		return 1;
	}

	// Parse //server/share
	const char* unc = argv[optind++];
	const char* p = unc;
	while (*p == '/' || *p == '\\')
		p++;
	const char* separator = p;
	while (*separator != '\0' && *separator != '/' && *separator != '\\')
		separator++;
	if (*separator == '\0' || separator == p) {
		fprintf(stderr, "mount_smbfs: invalid share specification \"%s\", "
			"expected //server/share\n", unc);
		return 1;
	}
	BString server(p, separator - p);
	while (*separator == '/' || *separator == '\\')
		separator++;
	BString share(separator);
	while (share.Length() > 0 && (share[share.Length() - 1] == '/'
			|| share[share.Length() - 1] == '\\')) {
		share.Truncate(share.Length() - 1);
	}
	if (share.Length() == 0) {
		fprintf(stderr, "mount_smbfs: no share name given\n");
		return 1;
	}

	BString mountPoint;
	if (optind < argc)
		mountPoint = argv[optind++];
	else
		mountPoint = default_mount_point(share.String());

	char passwordBuffer[256];
	if (password == NULL && user != NULL && user[0] != '\0' && !noPrompt) {
		BString prompt;
		prompt << "Password for " << user << "@" << server << ": ";
		if (!read_password(prompt.String(), passwordBuffer,
				sizeof(passwordBuffer))) {
			return 1;
		}
		size_t length = strlen(passwordBuffer);
		while (length > 0 && (passwordBuffer[length - 1] == '\n'
				|| passwordBuffer[length - 1] == '\r')) {
			passwordBuffer[--length] = '\0';
		}
		password = passwordBuffer;
	}

	BString parameters;
	parameters << "//" << server << "/" << share;
	append_option(parameters, "user", user);
	append_option(parameters, "password", password);
	append_option(parameters, "domain", domain);
	append_option(parameters, "port", port);
	if (sign)
		parameters << " sign";
	if (seal)
		parameters << " seal";
	if (extraOptions != NULL && extraOptions[0] != '\0')
		parameters << ' ' << extraOptions;

	// Check and create the mount point.
	bool exists = false;
	status_t check = check_mount_point(mountPoint.String(), &exists);
	if (check == B_NOT_ALLOWED) {
		fprintf(stderr, "mount_smbfs: refusing to mount over the system "
			"directory \"%s\"\n", mountPoint.String());
		return 1;
	}
	if (check == B_DIRECTORY_NOT_EMPTY) {
		fprintf(stderr, "mount_smbfs: mount point \"%s\" is not empty\n",
			mountPoint.String());
		return 1;
	}
	if (check != B_OK) {
		fprintf(stderr, "mount_smbfs: cannot use mount point \"%s\": %s\n",
			mountPoint.String(), strerror(check));
		return 1;
	}
	bool createdMountPoint = false;
	if (!exists) {
		if (mkdir(mountPoint.String(), 0755) != 0) {
			fprintf(stderr, "mount_smbfs: cannot create mount point \"%s\": "
				"%s\n", mountPoint.String(), strerror(errno));
			return 1;
		}
		createdMountPoint = true;
	}

	dev_t device = fs_mount_volume(mountPoint.String(), NULL, "smbfs",
		readOnly ? B_MOUNT_READ_ONLY : 0, parameters.String());
	// Do not keep the password around longer than needed.
	memset(passwordBuffer, 0, sizeof(passwordBuffer));

	if (device < 0) {
		fprintf(stderr, "mount_smbfs: mounting //%s/%s failed: %s\n",
			server.String(), share.String(), strerror(device));
		if (createdMountPoint)
			rmdir(mountPoint.String());
		return 1;
	}

	printf("Mounted //%s/%s at %s\n", server.String(), share.String(),
		mountPoint.String());
	return 0;
}
