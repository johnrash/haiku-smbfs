/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Crypto.h"

#include <string.h>


namespace smb2 {
namespace crypto {


// #pragma mark - helpers


static inline uint32_t
rotl32(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}


static inline uint32_t
rotr32(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}


static inline uint64_t
rotr64(uint64_t x, int n)
{
	return (x >> n) | (x << (64 - n));
}


static inline uint32_t
load_le32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
		| ((uint32_t)p[3] << 24);
}


static inline void
store_le32(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}


static inline void
store_le64(uint8_t* p, uint64_t v)
{
	store_le32(p, (uint32_t)v);
	store_le32(p + 4, (uint32_t)(v >> 32));
}


static inline uint32_t
load_be32(const uint8_t* p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
		| ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}


static inline void
store_be32(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}


static inline uint64_t
load_be64(const uint8_t* p)
{
	return ((uint64_t)load_be32(p) << 32) | load_be32(p + 4);
}


static inline void
store_be64(uint8_t* p, uint64_t v)
{
	store_be32(p, (uint32_t)(v >> 32));
	store_be32(p + 4, (uint32_t)v);
}


// #pragma mark - MD4


void
MD4::Reset()
{
	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;
	length = 0;
	bufferLength = 0;
}


static void
md4_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t x[16];
	for (int i = 0; i < 16; i++)
		x[i] = load_le32(block + i * 4);

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define FF(a, b, c, d, k, s) a = rotl32(a + F(b, c, d) + x[k], s)
#define GG(a, b, c, d, k, s) a = rotl32(a + G(b, c, d) + x[k] + 0x5a827999, s)
#define HH(a, b, c, d, k, s) a = rotl32(a + H(b, c, d) + x[k] + 0x6ed9eba1, s)

	FF(a, b, c, d, 0, 3); FF(d, a, b, c, 1, 7); FF(c, d, a, b, 2, 11); FF(b, c, d, a, 3, 19);
	FF(a, b, c, d, 4, 3); FF(d, a, b, c, 5, 7); FF(c, d, a, b, 6, 11); FF(b, c, d, a, 7, 19);
	FF(a, b, c, d, 8, 3); FF(d, a, b, c, 9, 7); FF(c, d, a, b, 10, 11); FF(b, c, d, a, 11, 19);
	FF(a, b, c, d, 12, 3); FF(d, a, b, c, 13, 7); FF(c, d, a, b, 14, 11); FF(b, c, d, a, 15, 19);

	GG(a, b, c, d, 0, 3); GG(d, a, b, c, 4, 5); GG(c, d, a, b, 8, 9); GG(b, c, d, a, 12, 13);
	GG(a, b, c, d, 1, 3); GG(d, a, b, c, 5, 5); GG(c, d, a, b, 9, 9); GG(b, c, d, a, 13, 13);
	GG(a, b, c, d, 2, 3); GG(d, a, b, c, 6, 5); GG(c, d, a, b, 10, 9); GG(b, c, d, a, 14, 13);
	GG(a, b, c, d, 3, 3); GG(d, a, b, c, 7, 5); GG(c, d, a, b, 11, 9); GG(b, c, d, a, 15, 13);

	HH(a, b, c, d, 0, 3); HH(d, a, b, c, 8, 9); HH(c, d, a, b, 4, 11); HH(b, c, d, a, 12, 15);
	HH(a, b, c, d, 2, 3); HH(d, a, b, c, 10, 9); HH(c, d, a, b, 6, 11); HH(b, c, d, a, 14, 15);
	HH(a, b, c, d, 1, 3); HH(d, a, b, c, 9, 9); HH(c, d, a, b, 5, 11); HH(b, c, d, a, 13, 15);
	HH(a, b, c, d, 3, 3); HH(d, a, b, c, 11, 9); HH(c, d, a, b, 7, 11); HH(b, c, d, a, 15, 15);

#undef F
#undef G
#undef H
#undef FF
#undef GG
#undef HH

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}


void
MD4::Update(const void* _data, size_t dataLength)
{
	const uint8_t* data = (const uint8_t*)_data;
	length += dataLength;

	if (bufferLength > 0) {
		size_t toCopy = 64 - bufferLength;
		if (toCopy > dataLength)
			toCopy = dataLength;
		memcpy(buffer + bufferLength, data, toCopy);
		bufferLength += toCopy;
		data += toCopy;
		dataLength -= toCopy;
		if (bufferLength < 64)
			return;
		md4_transform(state, buffer);
		bufferLength = 0;
	}

	while (dataLength >= 64) {
		md4_transform(state, data);
		data += 64;
		dataLength -= 64;
	}

	if (dataLength > 0) {
		memcpy(buffer, data, dataLength);
		bufferLength = dataLength;
	}
}


void
MD4::Final(uint8_t digest[16])
{
	uint64_t bitLength = length * 8;
	uint8_t pad = 0x80;
	Update(&pad, 1);
	uint8_t zero = 0;
	while (bufferLength != 56)
		Update(&zero, 1);
	uint8_t lengthBytes[8];
	store_le64(lengthBytes, bitLength);
	Update(lengthBytes, 8);
	for (int i = 0; i < 4; i++)
		store_le32(digest + i * 4, state[i]);
}


void
md4(const void* data, size_t length, uint8_t digest[16])
{
	MD4 context;
	context.Reset();
	context.Update(data, length);
	context.Final(digest);
}


// #pragma mark - MD5


static const uint32_t kMD5K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
	0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
	0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t kMD5S[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};


void
MD5::Reset()
{
	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;
	length = 0;
	bufferLength = 0;
}


static void
md5_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t m[16];
	for (int i = 0; i < 16; i++)
		m[i] = load_le32(block + i * 4);

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

	for (int i = 0; i < 64; i++) {
		uint32_t f;
		int g;
		if (i < 16) {
			f = (b & c) | (~b & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | (~d & c);
			g = (5 * i + 1) & 15;
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (3 * i + 5) & 15;
		} else {
			f = c ^ (b | ~d);
			g = (7 * i) & 15;
		}
		uint32_t temp = d;
		d = c;
		c = b;
		b = b + rotl32(a + f + kMD5K[i] + m[g], kMD5S[i]);
		a = temp;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}


void
MD5::Update(const void* _data, size_t dataLength)
{
	const uint8_t* data = (const uint8_t*)_data;
	length += dataLength;

	if (bufferLength > 0) {
		size_t toCopy = 64 - bufferLength;
		if (toCopy > dataLength)
			toCopy = dataLength;
		memcpy(buffer + bufferLength, data, toCopy);
		bufferLength += toCopy;
		data += toCopy;
		dataLength -= toCopy;
		if (bufferLength < 64)
			return;
		md5_transform(state, buffer);
		bufferLength = 0;
	}

	while (dataLength >= 64) {
		md5_transform(state, data);
		data += 64;
		dataLength -= 64;
	}

	if (dataLength > 0) {
		memcpy(buffer, data, dataLength);
		bufferLength = dataLength;
	}
}


void
MD5::Final(uint8_t digest[16])
{
	uint64_t bitLength = length * 8;
	uint8_t pad = 0x80;
	Update(&pad, 1);
	uint8_t zero = 0;
	while (bufferLength != 56)
		Update(&zero, 1);
	uint8_t lengthBytes[8];
	store_le64(lengthBytes, bitLength);
	Update(lengthBytes, 8);
	for (int i = 0; i < 4; i++)
		store_le32(digest + i * 4, state[i]);
}


void
md5(const void* data, size_t length, uint8_t digest[16])
{
	MD5 context;
	context.Reset();
	context.Update(data, length);
	context.Final(digest);
}


// #pragma mark - SHA-256


static const uint32_t kSHA256K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void
SHA256::Reset()
{
	state[0] = 0x6a09e667;
	state[1] = 0xbb67ae85;
	state[2] = 0x3c6ef372;
	state[3] = 0xa54ff53a;
	state[4] = 0x510e527f;
	state[5] = 0x9b05688c;
	state[6] = 0x1f83d9ab;
	state[7] = 0x5be0cd19;
	length = 0;
	bufferLength = 0;
}


static void
sha256_transform(uint32_t state[8], const uint8_t block[64])
{
	uint32_t w[64];
	for (int i = 0; i < 16; i++)
		w[i] = load_be32(block + i * 4);
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18)
			^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19)
			^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t temp1 = h + S1 + ch + kSHA256K[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}


void
SHA256::Update(const void* _data, size_t dataLength)
{
	const uint8_t* data = (const uint8_t*)_data;
	length += dataLength;

	if (bufferLength > 0) {
		size_t toCopy = 64 - bufferLength;
		if (toCopy > dataLength)
			toCopy = dataLength;
		memcpy(buffer + bufferLength, data, toCopy);
		bufferLength += toCopy;
		data += toCopy;
		dataLength -= toCopy;
		if (bufferLength < 64)
			return;
		sha256_transform(state, buffer);
		bufferLength = 0;
	}

	while (dataLength >= 64) {
		sha256_transform(state, data);
		data += 64;
		dataLength -= 64;
	}

	if (dataLength > 0) {
		memcpy(buffer, data, dataLength);
		bufferLength = dataLength;
	}
}


void
SHA256::Final(uint8_t digest[32])
{
	uint64_t bitLength = length * 8;
	uint8_t pad = 0x80;
	Update(&pad, 1);
	uint8_t zero = 0;
	while (bufferLength != 56)
		Update(&zero, 1);
	uint8_t lengthBytes[8];
	store_be64(lengthBytes, bitLength);
	Update(lengthBytes, 8);
	for (int i = 0; i < 8; i++)
		store_be32(digest + i * 4, state[i]);
}


void
sha256(const void* data, size_t length, uint8_t digest[32])
{
	SHA256 context;
	context.Reset();
	context.Update(data, length);
	context.Final(digest);
}


// #pragma mark - SHA-512


static const uint64_t kSHA512K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


void
SHA512::Reset()
{
	state[0] = 0x6a09e667f3bcc908ULL;
	state[1] = 0xbb67ae8584caa73bULL;
	state[2] = 0x3c6ef372fe94f82bULL;
	state[3] = 0xa54ff53a5f1d36f1ULL;
	state[4] = 0x510e527fade682d1ULL;
	state[5] = 0x9b05688c2b3e6c1fULL;
	state[6] = 0x1f83d9abfb41bd6bULL;
	state[7] = 0x5be0cd19137e2179ULL;
	lengthLow = 0;
	lengthHigh = 0;
	bufferLength = 0;
}


static void
sha512_transform(uint64_t state[8], const uint8_t block[128])
{
	uint64_t w[80];
	for (int i = 0; i < 16; i++)
		w[i] = load_be64(block + i * 8);
	for (int i = 16; i < 80; i++) {
		uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8)
			^ (w[i - 15] >> 7);
		uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61)
			^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

	for (int i = 0; i < 80; i++) {
		uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
		uint64_t ch = (e & f) ^ (~e & g);
		uint64_t temp1 = h + S1 + ch + kSHA512K[i] + w[i];
		uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
		uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint64_t temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}


void
SHA512::Update(const void* _data, size_t dataLength)
{
	const uint8_t* data = (const uint8_t*)_data;
	uint64_t oldLow = lengthLow;
	lengthLow += dataLength;
	if (lengthLow < oldLow)
		lengthHigh++;

	if (bufferLength > 0) {
		size_t toCopy = 128 - bufferLength;
		if (toCopy > dataLength)
			toCopy = dataLength;
		memcpy(buffer + bufferLength, data, toCopy);
		bufferLength += toCopy;
		data += toCopy;
		dataLength -= toCopy;
		if (bufferLength < 128)
			return;
		sha512_transform(state, buffer);
		bufferLength = 0;
	}

	while (dataLength >= 128) {
		sha512_transform(state, data);
		data += 128;
		dataLength -= 128;
	}

	if (dataLength > 0) {
		memcpy(buffer, data, dataLength);
		bufferLength = dataLength;
	}
}


void
SHA512::Final(uint8_t digest[64])
{
	uint64_t bitLengthLow = lengthLow << 3;
	uint64_t bitLengthHigh = (lengthHigh << 3) | (lengthLow >> 61);
	uint8_t pad = 0x80;
	Update(&pad, 1);
	uint8_t zero = 0;
	while (bufferLength != 112)
		Update(&zero, 1);
	uint8_t lengthBytes[16];
	store_be64(lengthBytes, bitLengthHigh);
	store_be64(lengthBytes + 8, bitLengthLow);
	Update(lengthBytes, 16);
	for (int i = 0; i < 8; i++)
		store_be64(digest + i * 8, state[i]);
}


void
sha512(const void* data, size_t length, uint8_t digest[64])
{
	SHA512 context;
	context.Reset();
	context.Update(data, length);
	context.Final(digest);
}


// #pragma mark - HMAC


void
HMACMD5::Init(const void* _key, size_t keyLength)
{
	uint8_t key[64];
	memset(key, 0, sizeof(key));
	if (keyLength > 64) {
		md5(_key, keyLength, key);
	} else
		memcpy(key, _key, keyLength);

	uint8_t pad[64];
	for (int i = 0; i < 64; i++)
		pad[i] = key[i] ^ 0x36;
	inner.Reset();
	inner.Update(pad, 64);

	for (int i = 0; i < 64; i++)
		pad[i] = key[i] ^ 0x5c;
	outer.Reset();
	outer.Update(pad, 64);

	memset(key, 0, sizeof(key));
	memset(pad, 0, sizeof(pad));
}


void
HMACMD5::Update(const void* data, size_t length)
{
	inner.Update(data, length);
}


void
HMACMD5::Final(uint8_t mac[16])
{
	uint8_t innerDigest[16];
	inner.Final(innerDigest);
	outer.Update(innerDigest, 16);
	outer.Final(mac);
}


void
hmac_md5(const void* key, size_t keyLength, const void* data, size_t length,
	uint8_t mac[16])
{
	HMACMD5 context;
	context.Init(key, keyLength);
	context.Update(data, length);
	context.Final(mac);
}


void
HMACSHA256::Init(const void* _key, size_t keyLength)
{
	uint8_t key[64];
	memset(key, 0, sizeof(key));
	if (keyLength > 64) {
		sha256(_key, keyLength, key);
	} else
		memcpy(key, _key, keyLength);

	uint8_t pad[64];
	for (int i = 0; i < 64; i++)
		pad[i] = key[i] ^ 0x36;
	inner.Reset();
	inner.Update(pad, 64);

	for (int i = 0; i < 64; i++)
		pad[i] = key[i] ^ 0x5c;
	outer.Reset();
	outer.Update(pad, 64);

	memset(key, 0, sizeof(key));
	memset(pad, 0, sizeof(pad));
}


void
HMACSHA256::Update(const void* data, size_t length)
{
	inner.Update(data, length);
}


void
HMACSHA256::Final(uint8_t mac[32])
{
	uint8_t innerDigest[32];
	inner.Final(innerDigest);
	outer.Update(innerDigest, 32);
	outer.Final(mac);
}


void
hmac_sha256(const void* key, size_t keyLength, const void* data, size_t length,
	uint8_t mac[32])
{
	HMACSHA256 context;
	context.Init(key, keyLength);
	context.Update(data, length);
	context.Final(mac);
}


// #pragma mark - AES-128


static uint8_t sSBox[256];
static uint32_t sTe0[256];
static uint32_t sTe1[256];
static uint32_t sTe2[256];
static uint32_t sTe3[256];
static bool sTablesInitialized = false;


static inline uint8_t
xtime(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}


static inline uint8_t
rotl8(uint8_t x, int n)
{
	return (uint8_t)((x << n) | (x >> (8 - n)));
}


void
Init()
{
	if (sTablesInitialized)
		return;

	// Generate the S-box from the GF(2^8) inverse and the affine transform
	// (the "p/q" method): p walks through the generator 3's powers while q
	// walks the inverses.
	uint8_t p = 1, q = 1;
	do {
		p = p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1b : 0);
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		if (q & 0x80)
			q ^= 0x09;
		uint8_t x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
		sSBox[p] = x ^ 0x63;
	} while (p != 1);
	sSBox[0] = 0x63;

	for (int i = 0; i < 256; i++) {
		uint8_t s = sSBox[i];
		uint8_t s2 = xtime(s);
		uint8_t s3 = s2 ^ s;
		// Te0[i] = (s2, s, s, s3) as bytes in big-endian word order
		uint32_t t = ((uint32_t)s2 << 24) | ((uint32_t)s << 16)
			| ((uint32_t)s << 8) | s3;
		sTe0[i] = t;
		sTe1[i] = (t >> 8) | (t << 24);
		sTe2[i] = (t >> 16) | (t << 16);
		sTe3[i] = (t >> 24) | (t << 8);
	}

	sTablesInitialized = true;
}


void
AES128::SetKey(const uint8_t key[16])
{
	if (!sTablesInitialized)
		Init();

	for (int i = 0; i < 4; i++)
		roundKeys[i] = load_be32(key + i * 4);

	uint8_t rcon = 0x01;
	for (int i = 4; i < 44; i++) {
		uint32_t temp = roundKeys[i - 1];
		if ((i & 3) == 0) {
			// RotWord + SubWord + Rcon
			temp = ((uint32_t)sSBox[(temp >> 16) & 0xff] << 24)
				| ((uint32_t)sSBox[(temp >> 8) & 0xff] << 16)
				| ((uint32_t)sSBox[temp & 0xff] << 8)
				| (uint32_t)sSBox[(temp >> 24) & 0xff];
			temp ^= (uint32_t)rcon << 24;
			rcon = xtime(rcon);
		}
		roundKeys[i] = roundKeys[i - 4] ^ temp;
	}
}


void
AES128::EncryptBlock(const uint8_t in[16], uint8_t out[16]) const
{
	uint32_t s0 = load_be32(in) ^ roundKeys[0];
	uint32_t s1 = load_be32(in + 4) ^ roundKeys[1];
	uint32_t s2 = load_be32(in + 8) ^ roundKeys[2];
	uint32_t s3 = load_be32(in + 12) ^ roundKeys[3];
	uint32_t t0, t1, t2, t3;

	const uint32_t* rk = roundKeys + 4;
	for (int round = 1; round < 10; round++) {
		t0 = sTe0[s0 >> 24] ^ sTe1[(s1 >> 16) & 0xff] ^ sTe2[(s2 >> 8) & 0xff]
			^ sTe3[s3 & 0xff] ^ rk[0];
		t1 = sTe0[s1 >> 24] ^ sTe1[(s2 >> 16) & 0xff] ^ sTe2[(s3 >> 8) & 0xff]
			^ sTe3[s0 & 0xff] ^ rk[1];
		t2 = sTe0[s2 >> 24] ^ sTe1[(s3 >> 16) & 0xff] ^ sTe2[(s0 >> 8) & 0xff]
			^ sTe3[s1 & 0xff] ^ rk[2];
		t3 = sTe0[s3 >> 24] ^ sTe1[(s0 >> 16) & 0xff] ^ sTe2[(s1 >> 8) & 0xff]
			^ sTe3[s2 & 0xff] ^ rk[3];
		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
		rk += 4;
	}

	// final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
	t0 = ((uint32_t)sSBox[s0 >> 24] << 24)
		| ((uint32_t)sSBox[(s1 >> 16) & 0xff] << 16)
		| ((uint32_t)sSBox[(s2 >> 8) & 0xff] << 8)
		| (uint32_t)sSBox[s3 & 0xff];
	t1 = ((uint32_t)sSBox[s1 >> 24] << 24)
		| ((uint32_t)sSBox[(s2 >> 16) & 0xff] << 16)
		| ((uint32_t)sSBox[(s3 >> 8) & 0xff] << 8)
		| (uint32_t)sSBox[s0 & 0xff];
	t2 = ((uint32_t)sSBox[s2 >> 24] << 24)
		| ((uint32_t)sSBox[(s3 >> 16) & 0xff] << 16)
		| ((uint32_t)sSBox[(s0 >> 8) & 0xff] << 8)
		| (uint32_t)sSBox[s1 & 0xff];
	t3 = ((uint32_t)sSBox[s3 >> 24] << 24)
		| ((uint32_t)sSBox[(s0 >> 16) & 0xff] << 16)
		| ((uint32_t)sSBox[(s1 >> 8) & 0xff] << 8)
		| (uint32_t)sSBox[s2 & 0xff];

	store_be32(out, t0 ^ rk[0]);
	store_be32(out + 4, t1 ^ rk[1]);
	store_be32(out + 8, t2 ^ rk[2]);
	store_be32(out + 12, t3 ^ rk[3]);
}


// #pragma mark - AES-CMAC (RFC 4493)


static void
cmac_shift_left(const uint8_t in[16], uint8_t out[16])
{
	uint8_t overflow = 0;
	for (int i = 15; i >= 0; i--) {
		out[i] = (uint8_t)((in[i] << 1) | overflow);
		overflow = (in[i] & 0x80) ? 1 : 0;
	}
}


void
AESCMAC::Init(const uint8_t key[16])
{
	aes.SetKey(key);

	uint8_t zero[16];
	uint8_t l[16];
	memset(zero, 0, sizeof(zero));
	aes.EncryptBlock(zero, l);

	cmac_shift_left(l, k1);
	if (l[0] & 0x80)
		k1[15] ^= 0x87;
	cmac_shift_left(k1, k2);
	if (k1[0] & 0x80)
		k2[15] ^= 0x87;

	memset(x, 0, sizeof(x));
	bufferLength = 0;
}


void
AESCMAC::Update(const void* _data, size_t length)
{
	const uint8_t* data = (const uint8_t*)_data;

	// Always keep the last (possibly complete) block in the buffer, so that
	// Final() can apply the correct subkey.
	while (length > 0) {
		if (bufferLength == 16) {
			uint8_t block[16];
			for (int i = 0; i < 16; i++)
				block[i] = x[i] ^ buffer[i];
			aes.EncryptBlock(block, x);
			bufferLength = 0;
		}
		size_t toCopy = 16 - bufferLength;
		if (toCopy > length)
			toCopy = length;
		memcpy(buffer + bufferLength, data, toCopy);
		bufferLength += toCopy;
		data += toCopy;
		length -= toCopy;
	}
}


void
AESCMAC::Final(uint8_t mac[16])
{
	uint8_t last[16];
	if (bufferLength == 16) {
		for (int i = 0; i < 16; i++)
			last[i] = buffer[i] ^ k1[i];
	} else {
		memset(last, 0, sizeof(last));
		memcpy(last, buffer, bufferLength);
		last[bufferLength] = 0x80;
		for (int i = 0; i < 16; i++)
			last[i] ^= k2[i];
	}
	for (int i = 0; i < 16; i++)
		last[i] ^= x[i];
	aes.EncryptBlock(last, mac);
}


void
aes_cmac(const uint8_t key[16], const void* data, size_t length,
	uint8_t mac[16])
{
	AESCMAC context;
	context.Init(key);
	context.Update(data, length);
	context.Final(mac);
}


// #pragma mark - AES-CCM (RFC 3610), M = 16, L = 4


static void
ccm_compute_tag(const AES128& aes, const uint8_t nonce[11], const uint8_t* aad,
	size_t aadLength, const uint8_t* plaintext, size_t length, uint8_t tag[16])
{
	uint8_t block[16];
	uint8_t x[16];

	// B0
	block[0] = (uint8_t)((aadLength > 0 ? 0x40 : 0) | (((16 - 2) / 2) << 3)
		| (4 - 1));
	memcpy(block + 1, nonce, 11);
	store_be32(block + 12, (uint32_t)length);
	aes.EncryptBlock(block, x);

	// AAD blocks
	if (aadLength > 0) {
		size_t offset = 0;
		memset(block, 0, sizeof(block));
		if (aadLength < 0xff00) {
			block[0] = (uint8_t)(aadLength >> 8);
			block[1] = (uint8_t)aadLength;
			offset = 2;
		} else {
			block[0] = 0xff;
			block[1] = 0xfe;
			store_be32(block + 2, (uint32_t)aadLength);
			offset = 6;
		}
		size_t remaining = aadLength;
		const uint8_t* p = aad;
		while (remaining > 0) {
			size_t toCopy = 16 - offset;
			if (toCopy > remaining)
				toCopy = remaining;
			memcpy(block + offset, p, toCopy);
			p += toCopy;
			remaining -= toCopy;
			for (int i = 0; i < 16; i++)
				block[i] ^= x[i];
			aes.EncryptBlock(block, x);
			memset(block, 0, sizeof(block));
			offset = 0;
		}
	}

	// payload blocks
	size_t remaining = length;
	const uint8_t* p = plaintext;
	while (remaining > 0) {
		size_t toCopy = remaining > 16 ? 16 : remaining;
		memset(block, 0, sizeof(block));
		memcpy(block, p, toCopy);
		p += toCopy;
		remaining -= toCopy;
		for (int i = 0; i < 16; i++)
			block[i] ^= x[i];
		aes.EncryptBlock(block, x);
	}

	memcpy(tag, x, 16);
}


static void
ccm_ctr(const AES128& aes, const uint8_t nonce[11], const uint8_t* in,
	size_t length, uint8_t* out, uint8_t s0[16])
{
	uint8_t counter[16];
	uint8_t stream[16];
	counter[0] = 4 - 1;
	memcpy(counter + 1, nonce, 11);
	store_be32(counter + 12, 0);
	aes.EncryptBlock(counter, s0);

	uint32_t i = 1;
	size_t remaining = length;
	while (remaining > 0) {
		store_be32(counter + 12, i++);
		aes.EncryptBlock(counter, stream);
		size_t toProcess = remaining > 16 ? 16 : remaining;
		for (size_t j = 0; j < toProcess; j++)
			out[j] = in[j] ^ stream[j];
		in += toProcess;
		out += toProcess;
		remaining -= toProcess;
	}
}


void
aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[11],
	const void* aad, size_t aadLength, const void* plaintext, size_t length,
	void* ciphertext, uint8_t tag[16])
{
	AES128 aes;
	aes.SetKey(key);

	uint8_t t[16];
	ccm_compute_tag(aes, nonce, (const uint8_t*)aad, aadLength,
		(const uint8_t*)plaintext, length, t);

	uint8_t s0[16];
	ccm_ctr(aes, nonce, (const uint8_t*)plaintext, length,
		(uint8_t*)ciphertext, s0);

	for (int i = 0; i < 16; i++)
		tag[i] = t[i] ^ s0[i];
}


bool
aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[11],
	const void* aad, size_t aadLength, const void* ciphertext, size_t length,
	void* plaintext, const uint8_t tag[16])
{
	AES128 aes;
	aes.SetKey(key);

	uint8_t s0[16];
	ccm_ctr(aes, nonce, (const uint8_t*)ciphertext, length,
		(uint8_t*)plaintext, s0);

	uint8_t t[16];
	ccm_compute_tag(aes, nonce, (const uint8_t*)aad, aadLength,
		(const uint8_t*)plaintext, length, t);
	for (int i = 0; i < 16; i++)
		t[i] ^= s0[i];

	if (!secure_equals(t, tag, 16)) {
		memset(plaintext, 0, length);
		return false;
	}
	return true;
}


// #pragma mark - AES-GCM


struct GHash {
	uint64_t	hHigh;
	uint64_t	hLow;
	uint64_t	yHigh;
	uint64_t	yLow;

	void Init(const uint8_t h[16])
	{
		hHigh = load_be64(h);
		hLow = load_be64(h + 8);
		yHigh = 0;
		yLow = 0;
	}

	// Multiply (yHigh, yLow) by H in GF(2^128) with the GCM bit ordering.
	void Multiply()
	{
		uint64_t zHigh = 0, zLow = 0;
		uint64_t vHigh = hHigh, vLow = hLow;
		uint64_t xHigh = yHigh, xLow = yLow;

		for (int i = 0; i < 128; i++) {
			uint64_t bit = i < 64 ? (xHigh >> (63 - i)) & 1
				: (xLow >> (127 - i)) & 1;
			uint64_t mask = (uint64_t)0 - bit;
			zHigh ^= vHigh & mask;
			zLow ^= vLow & mask;

			uint64_t lsb = vLow & 1;
			vLow = (vLow >> 1) | (vHigh << 63);
			vHigh >>= 1;
			vHigh ^= ((uint64_t)0 - lsb) & 0xe100000000000000ULL;
		}
		yHigh = zHigh;
		yLow = zLow;
	}

	void UpdateBlock(const uint8_t block[16])
	{
		yHigh ^= load_be64(block);
		yLow ^= load_be64(block + 8);
		Multiply();
	}

	void Update(const uint8_t* data, size_t length)
	{
		while (length >= 16) {
			UpdateBlock(data);
			data += 16;
			length -= 16;
		}
		if (length > 0) {
			uint8_t block[16];
			memset(block, 0, sizeof(block));
			memcpy(block, data, length);
			UpdateBlock(block);
		}
	}

	void Final(uint8_t out[16])
	{
		store_be64(out, yHigh);
		store_be64(out + 8, yLow);
	}
};


static void
gcm_ctr(const AES128& aes, const uint8_t iv[12], const uint8_t* in,
	size_t length, uint8_t* out)
{
	uint8_t counter[16];
	uint8_t stream[16];
	memcpy(counter, iv, 12);
	uint32_t count = 2;
	while (length > 0) {
		store_be32(counter + 12, count++);
		aes.EncryptBlock(counter, stream);
		size_t toProcess = length > 16 ? 16 : length;
		for (size_t j = 0; j < toProcess; j++)
			out[j] = in[j] ^ stream[j];
		in += toProcess;
		out += toProcess;
		length -= toProcess;
	}
}


static void
gcm_tag(const AES128& aes, const uint8_t iv[12], const uint8_t* aad,
	size_t aadLength, const uint8_t* ciphertext, size_t length, uint8_t tag[16])
{
	uint8_t zero[16];
	uint8_t h[16];
	memset(zero, 0, sizeof(zero));
	aes.EncryptBlock(zero, h);

	GHash ghash;
	ghash.Init(h);
	ghash.Update(aad, aadLength);
	ghash.Update(ciphertext, length);
	uint8_t lengths[16];
	store_be64(lengths, (uint64_t)aadLength * 8);
	store_be64(lengths + 8, (uint64_t)length * 8);
	ghash.UpdateBlock(lengths);
	uint8_t s[16];
	ghash.Final(s);

	uint8_t j0[16];
	memcpy(j0, iv, 12);
	store_be32(j0 + 12, 1);
	uint8_t ej0[16];
	aes.EncryptBlock(j0, ej0);
	for (int i = 0; i < 16; i++)
		tag[i] = s[i] ^ ej0[i];
}


void
aes_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12], const void* aad,
	size_t aadLength, const void* plaintext, size_t length, void* ciphertext,
	uint8_t tag[16])
{
	AES128 aes;
	aes.SetKey(key);
	gcm_ctr(aes, iv, (const uint8_t*)plaintext, length, (uint8_t*)ciphertext);
	gcm_tag(aes, iv, (const uint8_t*)aad, aadLength, (const uint8_t*)ciphertext,
		length, tag);
}


bool
aes_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12], const void* aad,
	size_t aadLength, const void* ciphertext, size_t length, void* plaintext,
	const uint8_t tag[16])
{
	AES128 aes;
	aes.SetKey(key);
	uint8_t computed[16];
	gcm_tag(aes, iv, (const uint8_t*)aad, aadLength, (const uint8_t*)ciphertext,
		length, computed);
	if (!secure_equals(computed, tag, 16))
		return false;
	gcm_ctr(aes, iv, (const uint8_t*)ciphertext, length, (uint8_t*)plaintext);
	return true;
}


// #pragma mark - RC4


void
rc4(const uint8_t* key, size_t keyLength, const void* _in, size_t length,
	void* _out)
{
	uint8_t s[256];
	for (int i = 0; i < 256; i++)
		s[i] = (uint8_t)i;
	uint8_t j = 0;
	for (int i = 0; i < 256; i++) {
		j = (uint8_t)(j + s[i] + key[i % keyLength]);
		uint8_t temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}

	const uint8_t* in = (const uint8_t*)_in;
	uint8_t* out = (uint8_t*)_out;
	uint8_t i = 0;
	j = 0;
	for (size_t k = 0; k < length; k++) {
		i = (uint8_t)(i + 1);
		j = (uint8_t)(j + s[i]);
		uint8_t temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		out[k] = in[k] ^ s[(uint8_t)(s[i] + s[j])];
	}
	memset(s, 0, sizeof(s));
}


// #pragma mark - KDF


void
kdf_sp800_108_128(const uint8_t* key, size_t keyLength, const void* label,
	size_t labelLength, const void* context, size_t contextLength,
	uint8_t out[16])
{
	HMACSHA256 hmac;
	hmac.Init(key, keyLength);
	uint8_t counter[4] = {0, 0, 0, 1};
	hmac.Update(counter, 4);
	hmac.Update(label, labelLength);
	uint8_t zero = 0;
	hmac.Update(&zero, 1);
	hmac.Update(context, contextLength);
	uint8_t bits[4] = {0, 0, 0, 128};
	hmac.Update(bits, 4);
	uint8_t digest[32];
	hmac.Final(digest);
	memcpy(out, digest, 16);
	memset(digest, 0, sizeof(digest));
}


// #pragma mark - misc


bool
secure_equals(const void* _a, const void* _b, size_t length)
{
	const uint8_t* a = (const uint8_t*)_a;
	const uint8_t* b = (const uint8_t*)_b;
	uint8_t diff = 0;
	for (size_t i = 0; i < length; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}


}	// namespace crypto
}	// namespace smb2
