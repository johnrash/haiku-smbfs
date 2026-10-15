/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef SMB2_UTF_H
#define SMB2_UTF_H

#include "Types.h"


namespace smb2 {


// Converts UTF-8 to UTF-16LE. Returns the number of bytes needed/written
// (without terminator), or -1 on invalid input. If out is NULL only the
// required size is computed. Does not write a terminator.
ssize_t Utf8ToUtf16LE(const char* in, size_t inLength, uint8* out,
	size_t outCapacity);

// Converts UTF-16LE to UTF-8. Returns the number of bytes needed/written
// (without terminator), or -1 on invalid input/insufficient space. Always
// NUL terminates when out != NULL and there is room.
ssize_t Utf16LEToUtf8(const uint8* in, size_t inLength, char* out,
	size_t outCapacity);

// Uppercases ASCII letters in place (sufficient for NTLM user names in
// practice; non-ASCII letters are left untouched).
void AsciiToUpper(char* string);


}	// namespace smb2


#endif	// SMB2_UTF_H
