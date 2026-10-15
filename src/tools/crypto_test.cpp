// Unit tests for the SMB2 crypto primitives against published test vectors.
#include "../smb2/Crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace smb2::crypto;

static int sFailures = 0;

static void
hex(const uint8_t* data, size_t len, char* out)
{
	for (size_t i = 0; i < len; i++)
		sprintf(out + i * 2, "%02x", data[i]);
	out[len * 2] = 0;
}

static void
check(const char* name, const uint8_t* got, size_t len, const char* expected)
{
	char buf[1024];
	hex(got, len, buf);
	if (strcmp(buf, expected) != 0) {
		printf("FAIL %s\n  got      %s\n  expected %s\n", name, buf, expected);
		sFailures++;
	} else
		printf("ok   %s\n", name);
}

static size_t
unhex(const char* s, uint8_t* out)
{
	size_t n = strlen(s) / 2;
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		sscanf(s + i * 2, "%2x", &v);
		out[i] = (uint8_t)v;
	}
	return n;
}

int
main(int argc, char** argv)
{
	Init();
	uint8_t d[64];
	uint8_t key[256], buf[256], buf2[256], tag[16], nonce[16], aad[64];

	md4("", 0, d); check("md4 empty", d, 16, "31d6cfe0d16ae931b73c59d7e0c089c0");
	md4("abc", 3, d); check("md4 abc", d, 16, "a448017aaf21d8525fc10ae87aa6729d");
	md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, d);
	check("md4 80 digits", d, 16, "e33b4ddc9c38f2199c3e7b164fcc0536");

	md5("", 0, d); check("md5 empty", d, 16, "d41d8cd98f00b204e9800998ecf8427e");
	md5("abc", 3, d); check("md5 abc", d, 16, "900150983cd24fb0d6963f7d28e17f72");
	md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, d);
	check("md5 80 digits", d, 16, "57edf4a22be3c955ac49da2e2107b67a");

	hmac_md5("key", 3, "The quick brown fox jumps over the lazy dog", 43, d);
	check("hmac-md5", d, 16, "80070713463e7749b90c2dc24911e275");

	sha256("abc", 3, d); check("sha256 abc", d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	sha256("", 0, d); check("sha256 empty", d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
	check("sha256 448 bits", d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	hmac_sha256("key", 3, "The quick brown fox jumps over the lazy dog", 43, d);
	check("hmac-sha256", d, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
	// RFC 4231 test case 2 (short key)
	hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
	check("hmac-sha256 rfc4231 tc2", d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	// RFC 4231 test case 6 (long key > block size)
	memset(key, 0xaa, 131);
	hmac_sha256(key, 131, "Test Using Larger Than Block-Size Key - Hash Key First", 54, d);
	check("hmac-sha256 rfc4231 tc6", d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

	sha512("abc", 3, d); check("sha512 abc", d, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	sha512("", 0, d); check("sha512 empty", d, 64, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
	sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, d);
	check("sha512 896 bits", d, 64, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
	// multi-part update across block boundary
	{
		SHA512 c; c.Reset();
		const char* m = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		c.Update(m, 100); c.Update(m + 100, 12); c.Final(d);
		check("sha512 multipart", d, 64, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
	}

	// AES-128 FIPS-197 C.1
	{
		AES128 aes;
		unhex("000102030405060708090a0b0c0d0e0f", key);
		aes.SetKey(key);
		unhex("00112233445566778899aabbccddeeff", buf);
		aes.EncryptBlock(buf, d);
		check("aes128 fips197", d, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
		// NIST SP800-38A F.1.1 ECB
		unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
		aes.SetKey(key);
		unhex("6bc1bee22e409f96e93d7e117393172a", buf);
		aes.EncryptBlock(buf, d);
		check("aes128 sp800-38a", d, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
	}

	// AES-CMAC RFC 4493
	{
		unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
		const char* msgHex = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
		unhex(msgHex, buf);
		aes_cmac(key, buf, 0, d); check("cmac empty", d, 16, "bb1d6929e95937287fa37d129b756746");
		aes_cmac(key, buf, 16, d); check("cmac 16", d, 16, "070a16b46b4d4144f79bdd9dd04a287c");
		aes_cmac(key, buf, 40, d); check("cmac 40", d, 16, "dfa66747de9ae63030ca32611497c827");
		aes_cmac(key, buf, 64, d); check("cmac 64", d, 16, "51f0bebf7e3b9d92fc49741779363cfe");
		AESCMAC c; c.Init(key); c.Update(buf, 7); c.Update(buf + 7, 20); c.Update(buf + 27, 13); c.Final(d);
		check("cmac 40 multipart", d, 16, "dfa66747de9ae63030ca32611497c827");
		c.Init(key); c.Update(buf, 16); c.Update(buf + 16, 48); c.Final(d);
		check("cmac 64 multipart", d, 16, "51f0bebf7e3b9d92fc49741779363cfe");
	}

	// AES-GCM NIST test cases
	{
		memset(key, 0, 16); memset(nonce, 0, 12);
		aes_gcm_encrypt(key, nonce, NULL, 0, NULL, 0, buf, tag);
		check("gcm tc1 tag", tag, 16, "58e2fccefa7e3061367f1d57a4e7455a");
		memset(buf, 0, 16);
		aes_gcm_encrypt(key, nonce, NULL, 0, buf, 16, buf2, tag);
		check("gcm tc2 ct", buf2, 16, "0388dace60b6a392f328c2b971b2fe78");
		check("gcm tc2 tag", tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");
		unhex("feffe9928665731c6d6a8f9467308308", key);
		unhex("cafebabefacedbaddecaf888", nonce);
		size_t n = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", buf);
		aes_gcm_encrypt(key, nonce, NULL, 0, buf, n, buf2, tag);
		check("gcm tc3 ct", buf2, n, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
		check("gcm tc3 tag", tag, 16, "4d5c2af327cd64a62cf35abd2ba6fab4");
		size_t an = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
		aes_gcm_encrypt(key, nonce, aad, an, buf, 60, buf2, tag);
		check("gcm tc4 ct", buf2, 60, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
		check("gcm tc4 tag", tag, 16, "5bc94fbc3221a5db94fae95ae7121a47");
		uint8_t dec[64];
		bool ok = aes_gcm_decrypt(key, nonce, aad, an, buf2, 60, dec, tag);
		if (!ok || memcmp(dec, buf, 60) != 0) { printf("FAIL gcm tc4 decrypt\n"); sFailures++; } else printf("ok   gcm tc4 decrypt\n");
		tag[0] ^= 1;
		if (aes_gcm_decrypt(key, nonce, aad, an, buf2, 60, dec, tag)) { printf("FAIL gcm tamper not detected\n"); sFailures++; } else printf("ok   gcm tamper detected\n");
	}

	// RC4 (Wikipedia vectors)
	{
		rc4((const uint8_t*)"Key", 3, "Plaintext", 9, d);
		check("rc4 Key/Plaintext", d, 9, "bbf316e8d940af0ad3");
		rc4((const uint8_t*)"Wiki", 4, "pedia", 5, d);
		check("rc4 Wiki/pedia", d, 5, "1021bf0420");
	}

	// NTLMv2 vectors from MS-NLMP 4.2.4
	{
		// NTOWFv2 = HMAC_MD5(MD4(UTF16(password)), UTF16(upper(user) + domain))
		uint8_t pw[16]; unhex("500061007300730077006f0072006400", pw); // "Password"
		uint8_t nt[16]; md4(pw, 16, nt);
		check("ntlm NT hash", nt, 16, "a4f49c406510bdcab6824ee7c30fd852");
		uint8_t ud[22]; unhex("5500530045005200440006f006d00610069006e00", ud); // "USER" + "Domain" — careful below
		// build properly: "USER" "Domain" in UTF-16LE
		const char* userDomain = "USERDomain";
		uint8_t ud2[20];
		for (int i = 0; i < 10; i++) { ud2[i * 2] = userDomain[i]; ud2[i * 2 + 1] = 0; }
		uint8_t ntowf[16]; hmac_md5(nt, 16, ud2, 20, ntowf);
		check("ntlm NTOWFv2", ntowf, 16, "0c868a403bfd7a93a3001ef22ef02e3f");
		// temp blob from the spec
		uint8_t temp[64]; size_t tn = unhex("0101000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000000000000", temp);
		(void)tn; (void)ud;
		// The spec's temp: 0101 0000 00000000 (reserved) time(8)=0 clientchallenge(8)=aa.. 00000000 avpairs 00000000
		uint8_t temp2[80]; size_t tn2 = 0;
		const char* tempHex = "01010000" "00000000" "0000000000000000" "aaaaaaaaaaaaaaaa" "00000000"
			"02000c0044006f006d00610069006e00" "01000c00530065007200760065007200" "00000000" "00000000";
		tn2 = unhex(tempHex, temp2);
		uint8_t sc[8]; unhex("0123456789abcdef", sc);
		HMACMD5 h; h.Init(ntowf, 16); h.Update(sc, 8); h.Update(temp2, tn2); uint8_t proof[16]; h.Final(proof);
		check("ntlm NTProofStr", proof, 16, "68cd0ab851e51c96aabc927bebef6a1c");
		uint8_t sbk[16]; hmac_md5(ntowf, 16, proof, 16, sbk);
		check("ntlm SessionBaseKey", sbk, 16, "8de40ccadbc14a82f15cb0ad0de95ca3");
		uint8_t cc[8]; memset(cc, 0xaa, 8);
		h.Init(ntowf, 16); h.Update(sc, 8); h.Update(cc, 8); uint8_t lm[16]; h.Final(lm);
		check("ntlm LMv2", lm, 16, "86c35097ac9cec102554764a57cccc19");
		uint8_t rsk[16]; memset(rsk, 0x55, 16); uint8_t enc[16];
		rc4(sbk, 16, rsk, 16, enc);
		check("ntlm EncryptedRandomSessionKey", enc, 16, "c5dad2544fc9799094ce1ce90bc9d03e");
	}

	// KDF sanity: compare with Python reference computed externally (printed by test harness)
	{
		unhex("000102030405060708090a0b0c0d0e0f", key);
		kdf_sp800_108_128(key, 16, "SMB2AESCMAC\0", 12, "SmbSign\0", 8, d);
		char out[64]; hex(d, 16, out);
		printf("kdf SMB2AESCMAC/SmbSign = %s\n", out);
	}

	// CCM: print values for external cross-check with Python
	if (argc > 1 && strcmp(argv[1], "ccm") == 0) {
		unhex("000102030405060708090a0b0c0d0e0f", key);
		unhex("0102030405060708090a0b", nonce);
		size_t an = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
		size_t n = unhex("48656c6c6f2c20534d4232206f76657220434346204d6f64652100112233445566778899aabbccddeeff00", buf);
		aes_ccm_encrypt(key, nonce, aad, an, buf, n, buf2, tag);
		char out[512]; hex(buf2, n, out); printf("ccm ct=%s\n", out); hex(tag, 16, out); printf("ccm tag=%s\n", out);
		uint8_t dec[64];
		bool ok = aes_ccm_decrypt(key, nonce, aad, an, buf2, n, dec, tag);
		printf("%s ccm roundtrip\n", ok && memcmp(dec, buf, n) == 0 ? "ok  " : "FAIL");
		if (!(ok && memcmp(dec, buf, n) == 0)) sFailures++;
		// in place
		memcpy(buf2, buf, n);
		aes_ccm_encrypt(key, nonce, aad, an, buf2, n, buf2, tag);
		ok = aes_ccm_decrypt(key, nonce, aad, an, buf2, n, buf2, tag);
		printf("%s ccm in-place roundtrip\n", ok && memcmp(buf2, buf, n) == 0 ? "ok  " : "FAIL");
		// gcm with same data for python cross-check
		uint8_t iv[12]; unhex("0102030405060708090a0b0c", iv);
		aes_gcm_encrypt(key, iv, aad, an, buf, n, buf2, tag);
		hex(buf2, n, out); printf("gcm ct=%s\n", out); hex(tag, 16, out); printf("gcm tag=%s\n", out);
	}

	printf("%d failure(s)\n", sFailures);
	return sFailures == 0 ? 0 : 1;
}
