/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Utf.h"


namespace smb2 {


ssize_t
Utf8ToUtf16LE(const char* _in, size_t inLength, uint8* out, size_t outCapacity)
{
	const uint8* in = (const uint8*)_in;
	size_t i = 0;
	size_t outLength = 0;

	while (i < inLength) {
		uint32 c = in[i];
		size_t extra;
		if (c < 0x80) {
			extra = 0;
		} else if ((c & 0xe0) == 0xc0) {
			c &= 0x1f;
			extra = 1;
		} else if ((c & 0xf0) == 0xe0) {
			c &= 0x0f;
			extra = 2;
		} else if ((c & 0xf8) == 0xf0) {
			c &= 0x07;
			extra = 3;
		} else
			return -1;

		if (extra > 0 && i + extra >= inLength)
			return -1;
		i++;
		for (size_t k = 0; k < extra; k++) {
			uint8 b = in[i++];
			if ((b & 0xc0) != 0x80)
				return -1;
			c = (c << 6) | (b & 0x3f);
		}

		if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
			return -1;

		if (c >= 0x10000) {
			c -= 0x10000;
			uint16 high = (uint16)(0xd800 | (c >> 10));
			uint16 low = (uint16)(0xdc00 | (c & 0x3ff));
			if (out != NULL) {
				if (outLength + 4 > outCapacity)
					return -1;
				out[outLength] = (uint8)high;
				out[outLength + 1] = (uint8)(high >> 8);
				out[outLength + 2] = (uint8)low;
				out[outLength + 3] = (uint8)(low >> 8);
			}
			outLength += 4;
		} else {
			if (out != NULL) {
				if (outLength + 2 > outCapacity)
					return -1;
				out[outLength] = (uint8)c;
				out[outLength + 1] = (uint8)(c >> 8);
			}
			outLength += 2;
		}
	}

	return (ssize_t)outLength;
}


ssize_t
Utf16LEToUtf8(const uint8* in, size_t inLength, char* out, size_t outCapacity)
{
	size_t i = 0;
	size_t outLength = 0;
	inLength &= ~(size_t)1;

	while (i < inLength) {
		uint32 c = (uint32)in[i] | ((uint32)in[i + 1] << 8);
		i += 2;
		if (c >= 0xd800 && c <= 0xdbff) {
			if (i + 2 > inLength)
				return -1;
			uint32 low = (uint32)in[i] | ((uint32)in[i + 1] << 8);
			if (low < 0xdc00 || low > 0xdfff)
				return -1;
			i += 2;
			c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
		} else if (c >= 0xdc00 && c <= 0xdfff)
			return -1;

		uint8 bytes[4];
		size_t count;
		if (c < 0x80) {
			bytes[0] = (uint8)c;
			count = 1;
		} else if (c < 0x800) {
			bytes[0] = (uint8)(0xc0 | (c >> 6));
			bytes[1] = (uint8)(0x80 | (c & 0x3f));
			count = 2;
		} else if (c < 0x10000) {
			bytes[0] = (uint8)(0xe0 | (c >> 12));
			bytes[1] = (uint8)(0x80 | ((c >> 6) & 0x3f));
			bytes[2] = (uint8)(0x80 | (c & 0x3f));
			count = 3;
		} else {
			bytes[0] = (uint8)(0xf0 | (c >> 18));
			bytes[1] = (uint8)(0x80 | ((c >> 12) & 0x3f));
			bytes[2] = (uint8)(0x80 | ((c >> 6) & 0x3f));
			bytes[3] = (uint8)(0x80 | (c & 0x3f));
			count = 4;
		}

		if (out != NULL) {
			if (outLength + count + 1 > outCapacity)
				return -1;
			for (size_t k = 0; k < count; k++)
				out[outLength + k] = (char)bytes[k];
		}
		outLength += count;
	}

	if (out != NULL) {
		if (outLength >= outCapacity)
			return -1;
		out[outLength] = '\0';
	}
	return (ssize_t)outLength;
}


void
AsciiToUpper(char* string)
{
	for (; *string != '\0'; string++) {
		if (*string >= 'a' && *string <= 'z')
			*string = (char)(*string - 'a' + 'A');
	}
}


}	// namespace smb2
