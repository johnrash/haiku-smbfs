/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Little-endian packet builder and bounds checked reader.
 */
#ifndef SMB2_BUFFER_H
#define SMB2_BUFFER_H

#include "Types.h"

#include <stdlib.h>
#include <string.h>


namespace smb2 {


static inline uint16
LoadLE16(const uint8* p)
{
	return (uint16)(p[0] | (p[1] << 8));
}


static inline uint32
LoadLE32(const uint8* p)
{
	return (uint32)p[0] | ((uint32)p[1] << 8) | ((uint32)p[2] << 16)
		| ((uint32)p[3] << 24);
}


static inline uint64
LoadLE64(const uint8* p)
{
	return (uint64)LoadLE32(p) | ((uint64)LoadLE32(p + 4) << 32);
}


static inline void
StoreLE16(uint8* p, uint16 value)
{
	p[0] = (uint8)value;
	p[1] = (uint8)(value >> 8);
}


static inline void
StoreLE32(uint8* p, uint32 value)
{
	p[0] = (uint8)value;
	p[1] = (uint8)(value >> 8);
	p[2] = (uint8)(value >> 16);
	p[3] = (uint8)(value >> 24);
}


static inline void
StoreLE64(uint8* p, uint64 value)
{
	StoreLE32(p, (uint32)value);
	StoreLE32(p + 4, (uint32)(value >> 32));
}


class Packet {
public:
	Packet()
		:
		fData(NULL),
		fLength(0),
		fCapacity(0),
		fFailed(false)
	{
	}

	~Packet()
	{
		free(fData);
	}

	uint8* Data() const { return fData; }
	size_t Length() const { return fLength; }
	bool Failed() const { return fFailed; }

	void Reset()
	{
		fLength = 0;
		fFailed = false;
	}

	bool Reserve(size_t capacity)
	{
		if (capacity <= fCapacity)
			return true;
		size_t newCapacity = fCapacity == 0 ? 256 : fCapacity;
		while (newCapacity < capacity)
			newCapacity *= 2;
		uint8* data = (uint8*)realloc(fData, newCapacity);
		if (data == NULL) {
			fFailed = true;
			return false;
		}
		fData = data;
		fCapacity = newCapacity;
		return true;
	}

	uint8* Grow(size_t count)
	{
		// Always keep a valid pointer, even for empty growth.
		if (!Reserve(fLength + (count > 0 ? count : 1)))
			return NULL;
		uint8* p = fData + fLength;
		fLength += count;
		return p;
	}

	void PutU8(uint8 value)
	{
		uint8* p = Grow(1);
		if (p != NULL)
			*p = value;
	}

	void PutU16(uint16 value)
	{
		uint8* p = Grow(2);
		if (p != NULL)
			StoreLE16(p, value);
	}

	void PutU32(uint32 value)
	{
		uint8* p = Grow(4);
		if (p != NULL)
			StoreLE32(p, value);
	}

	void PutU64(uint64 value)
	{
		uint8* p = Grow(8);
		if (p != NULL)
			StoreLE64(p, value);
	}

	void PutBytes(const void* data, size_t length)
	{
		if (length == 0)
			return;
		uint8* p = Grow(length);
		if (p != NULL)
			memcpy(p, data, length);
	}

	void PutZeros(size_t length)
	{
		if (length == 0)
			return;
		uint8* p = Grow(length);
		if (p != NULL)
			memset(p, 0, length);
	}

	// Pads with zeros so that the length becomes a multiple of alignment.
	void Align(size_t alignment)
	{
		size_t rest = fLength % alignment;
		if (rest != 0)
			PutZeros(alignment - rest);
	}

	void SetU8(size_t offset, uint8 value)
	{
		if (offset + 1 <= fLength)
			fData[offset] = value;
	}

	void SetU16(size_t offset, uint16 value)
	{
		if (offset + 2 <= fLength)
			StoreLE16(fData + offset, value);
	}

	void SetU32(size_t offset, uint32 value)
	{
		if (offset + 4 <= fLength)
			StoreLE32(fData + offset, value);
	}

	void SetU64(size_t offset, uint64 value)
	{
		if (offset + 8 <= fLength)
			StoreLE64(fData + offset, value);
	}

	void SetBytes(size_t offset, const void* data, size_t length)
	{
		if (offset + length <= fLength)
			memcpy(fData + offset, data, length);
	}

	void Truncate(size_t length)
	{
		if (length < fLength)
			fLength = length;
	}

	// Detach the buffer; the caller becomes responsible for free()ing it.
	uint8* Detach()
	{
		uint8* data = fData;
		fData = NULL;
		fLength = 0;
		fCapacity = 0;
		return data;
	}

private:
	Packet(const Packet&);
	Packet& operator=(const Packet&);

			uint8*				fData;
			size_t				fLength;
			size_t				fCapacity;
			bool				fFailed;
};


class Reader {
public:
	Reader(const uint8* data, size_t length)
		:
		fData(data),
		fLength(length),
		fPosition(0)
	{
	}

	const uint8* Data() const { return fData; }
	size_t Length() const { return fLength; }
	size_t Position() const { return fPosition; }
	size_t Remaining() const { return fLength - fPosition; }
	const uint8* Current() const { return fData + fPosition; }
	bool HasBytes(size_t count) const { return count <= fLength - fPosition; }

	bool Seek(size_t position)
	{
		if (position > fLength)
			return false;
		fPosition = position;
		return true;
	}

	bool Skip(size_t count)
	{
		if (!HasBytes(count))
			return false;
		fPosition += count;
		return true;
	}

	bool U8(uint8& value)
	{
		if (!HasBytes(1))
			return false;
		value = fData[fPosition++];
		return true;
	}

	bool U16(uint16& value)
	{
		if (!HasBytes(2))
			return false;
		value = LoadLE16(fData + fPosition);
		fPosition += 2;
		return true;
	}

	bool U32(uint32& value)
	{
		if (!HasBytes(4))
			return false;
		value = LoadLE32(fData + fPosition);
		fPosition += 4;
		return true;
	}

	bool U64(uint64& value)
	{
		if (!HasBytes(8))
			return false;
		value = LoadLE64(fData + fPosition);
		fPosition += 8;
		return true;
	}

	bool Bytes(void* buffer, size_t length)
	{
		if (!HasBytes(length))
			return false;
		memcpy(buffer, fData + fPosition, length);
		fPosition += length;
		return true;
	}

	// Validates that [offset, offset + length) lies inside the buffer.
	bool ValidRange(size_t offset, size_t length) const
	{
		return offset <= fLength && length <= fLength - offset;
	}

private:
			const uint8*		fData;
			size_t				fLength;
			size_t				fPosition;
};


}	// namespace smb2


#endif	// SMB2_BUFFER_H
