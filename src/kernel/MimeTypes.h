/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef SMBFS_MIME_TYPES_H
#define SMBFS_MIME_TYPES_H


// Returns the MIME type for a file name based on its extension, or NULL if
// the extension is unknown. Used to provide a virtual BEOS:TYPE attribute,
// so that Tracker and other applications know what to do with files on a
// share without having to sniff (or write attributes).
const char* mime_type_for_file_name(const char* name);


#endif	// SMBFS_MIME_TYPES_H
