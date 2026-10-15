/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * Self-contained cryptographic primitives needed by the SMB2/3 client:
 * MD4 (NT hash), MD5/HMAC-MD5 (NTLMv2), SHA-256/HMAC-SHA256 (SMB2 signing,
 * SP800-108 KDF), SHA-512 (SMB 3.1.1 pre-authentication integrity),
 * AES-128 with CMAC (SMB3 signing), CCM and GCM (SMB3 encryption), RC4
 * (NTLMSSP key exchange).
 *
 * The code is freestanding (no libc beyond memcpy/memset) so it can be used
 * from the Haiku kernel as well as from userland.
 */
#ifndef SMB2_CRYPTO_H
#define SMB2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>


namespace smb2 {
namespace crypto {


// Must be called once before using AES (builds the S-box tables).
void Init();


struct MD4 {
	uint32_t	state[4];
	uint64_t	length;
	uint8_t		buffer[64];
	size_t		bufferLength;

	void Reset();
	void Update(const void* data, size_t length);
	void Final(uint8_t digest[16]);
};


struct MD5 {
	uint32_t	state[4];
	uint64_t	length;
	uint8_t		buffer[64];
	size_t		bufferLength;

	void Reset();
	void Update(const void* data, size_t length);
	void Final(uint8_t digest[16]);
};


struct SHA256 {
	uint32_t	state[8];
	uint64_t	length;
	uint8_t		buffer[64];
	size_t		bufferLength;

	void Reset();
	void Update(const void* data, size_t length);
	void Final(uint8_t digest[32]);
};


struct SHA512 {
	uint64_t	state[8];
	uint64_t	lengthLow;
	uint64_t	lengthHigh;
	uint8_t		buffer[128];
	size_t		bufferLength;

	void Reset();
	void Update(const void* data, size_t length);
	void Final(uint8_t digest[64]);
};


void md4(const void* data, size_t length, uint8_t digest[16]);
void md5(const void* data, size_t length, uint8_t digest[16]);
void sha256(const void* data, size_t length, uint8_t digest[32]);
void sha512(const void* data, size_t length, uint8_t digest[64]);


struct HMACMD5 {
	MD5			inner;
	MD5			outer;

	void Init(const void* key, size_t keyLength);
	void Update(const void* data, size_t length);
	void Final(uint8_t mac[16]);
};


struct HMACSHA256 {
	SHA256		inner;
	SHA256		outer;

	void Init(const void* key, size_t keyLength);
	void Update(const void* data, size_t length);
	void Final(uint8_t mac[32]);
};


void hmac_md5(const void* key, size_t keyLength, const void* data,
	size_t length, uint8_t mac[16]);
void hmac_sha256(const void* key, size_t keyLength, const void* data,
	size_t length, uint8_t mac[32]);


struct AES128 {
	uint32_t	roundKeys[44];

	void SetKey(const uint8_t key[16]);
	void EncryptBlock(const uint8_t in[16], uint8_t out[16]) const;
};


struct AESCMAC {
	AES128		aes;
	uint8_t		k1[16];
	uint8_t		k2[16];
	uint8_t		x[16];
	uint8_t		buffer[16];
	size_t		bufferLength;

	void Init(const uint8_t key[16]);
	void Update(const void* data, size_t length);
	void Final(uint8_t mac[16]);
};


void aes_cmac(const uint8_t key[16], const void* data, size_t length,
	uint8_t mac[16]);


// AES-128-CCM as used by SMB 3.x: 16 byte tag, 11 byte nonce (L = 4).
// Encryption/decryption may be done in place (output == input).
void aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[11],
	const void* aad, size_t aadLength, const void* plaintext, size_t length,
	void* ciphertext, uint8_t tag[16]);
bool aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[11],
	const void* aad, size_t aadLength, const void* ciphertext, size_t length,
	void* plaintext, const uint8_t tag[16]);

// AES-128-GCM with 12 byte IV and 16 byte tag, as used by SMB 3.1.1.
void aes_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
	const void* aad, size_t aadLength, const void* plaintext, size_t length,
	void* ciphertext, uint8_t tag[16]);
bool aes_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
	const void* aad, size_t aadLength, const void* ciphertext, size_t length,
	void* plaintext, const uint8_t tag[16]);


void rc4(const uint8_t* key, size_t keyLength, const void* in, size_t length,
	void* out);


// NIST SP800-108 KDF in counter mode with HMAC-SHA256, 128 bit output, as
// specified by MS-SMB2 3.1.4.2. Label and context are passed including their
// terminating NUL byte where the specification requires it.
void kdf_sp800_108_128(const uint8_t* key, size_t keyLength, const void* label,
	size_t labelLength, const void* context, size_t contextLength,
	uint8_t out[16]);


// Constant time comparison.
bool secure_equals(const void* a, const void* b, size_t length);


}	// namespace crypto
}	// namespace smb2


#endif	// SMB2_CRYPTO_H
