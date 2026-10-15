/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Ntlm.h"

#include <stdlib.h>
#include <string.h>

#include "Crypto.h"
#include "Platform.h"
#include "Utf.h"


namespace smb2 {


enum {
	NTLMSSP_NEGOTIATE_UNICODE					= 0x00000001,
	NTLMSSP_NEGOTIATE_OEM						= 0x00000002,
	NTLMSSP_REQUEST_TARGET						= 0x00000004,
	NTLMSSP_NEGOTIATE_SIGN						= 0x00000010,
	NTLMSSP_NEGOTIATE_SEAL						= 0x00000020,
	NTLMSSP_NEGOTIATE_DATAGRAM					= 0x00000040,
	NTLMSSP_NEGOTIATE_LM_KEY					= 0x00000080,
	NTLMSSP_NEGOTIATE_NTLM						= 0x00000200,
	NTLMSSP_ANONYMOUS							= 0x00000800,
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED		= 0x00001000,
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED	= 0x00002000,
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN				= 0x00008000,
	NTLMSSP_TARGET_TYPE_DOMAIN					= 0x00010000,
	NTLMSSP_TARGET_TYPE_SERVER					= 0x00020000,
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY	= 0x00080000,
	NTLMSSP_NEGOTIATE_IDENTIFY					= 0x00100000,
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY			= 0x00400000,
	NTLMSSP_NEGOTIATE_TARGET_INFO				= 0x00800000,
	NTLMSSP_NEGOTIATE_VERSION					= 0x02000000,
	NTLMSSP_NEGOTIATE_128						= 0x20000000,
	NTLMSSP_NEGOTIATE_KEY_EXCH					= 0x40000000,
	NTLMSSP_NEGOTIATE_56						= 0x80000000
};

enum {
	MsvAvEOL				= 0x0000,
	MsvAvNbComputerName		= 0x0001,
	MsvAvNbDomainName		= 0x0002,
	MsvAvDnsComputerName	= 0x0003,
	MsvAvDnsDomainName		= 0x0004,
	MsvAvDnsTreeName		= 0x0005,
	MsvAvFlags				= 0x0006,
	MsvAvTimestamp			= 0x0007,
	MsvAvSingleHost			= 0x0008,
	MsvAvTargetName			= 0x0009,
	MsvAvChannelBindings	= 0x000a
};

static const uint8 kNtlmSignature[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

// Version field: Windows 10 build 19041, NTLMSSP revision 15.
static const uint8 kNtlmVersion[8] = {10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f};

static const uint32 kClientFlags = NTLMSSP_NEGOTIATE_UNICODE
	| NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_SIGN
	| NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_VERSION
	| NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56;


static void
put_field(Packet& out, size_t length, size_t offset)
{
	out.PutU16((uint16)length);
	out.PutU16((uint16)length);
	out.PutU32((uint32)offset);
}


// Appends UTF-16LE encoded string to the packet, returning its byte length.
static size_t
put_utf16(Packet& out, const char* string)
{
	if (string == NULL || string[0] == '\0')
		return 0;
	size_t length = strlen(string);
	ssize_t size = Utf8ToUtf16LE(string, length, NULL, 0);
	if (size < 0)
		return 0;
	uint8* buffer = out.Grow(size);
	if (buffer == NULL)
		return 0;
	Utf8ToUtf16LE(string, length, buffer, size);
	return (size_t)size;
}


NtlmContext::NtlmContext()
	:
	fUser(NULL),
	fPassword(NULL),
	fDomain(NULL),
	fWorkstation(NULL),
	fServerFlags(0),
	fTargetInfo(NULL),
	fTargetInfoLength(0),
	fNegotiateMessage(NULL),
	fNegotiateLength(0),
	fChallengeMessage(NULL),
	fChallengeLength(0),
	fHasSessionKey(false)
{
	memset(fServerChallenge, 0, sizeof(fServerChallenge));
	memset(fSessionKey, 0, sizeof(fSessionKey));
	fTargetName[0] = '\0';
}


NtlmContext::~NtlmContext()
{
	if (fPassword != NULL)
		memset(fPassword, 0, strlen(fPassword));
	free(fUser);
	free(fPassword);
	free(fDomain);
	free(fWorkstation);
	free(fTargetInfo);
	free(fNegotiateMessage);
	free(fChallengeMessage);
	memset(fSessionKey, 0, sizeof(fSessionKey));
}


status_t
NtlmContext::_SetString(char** field, const char* value)
{
	free(*field);
	*field = NULL;
	if (value == NULL)
		return B_OK;
	*field = strdup(value);
	return *field != NULL ? B_OK : B_NO_MEMORY;
}


status_t
NtlmContext::SetCredentials(const char* user, const char* password,
	const char* domain, const char* workstation)
{
	status_t status = _SetString(&fUser, user);
	if (status == B_OK)
		status = _SetString(&fPassword, password);
	if (status == B_OK)
		status = _SetString(&fDomain, domain);
	if (status == B_OK)
		status = _SetString(&fWorkstation, workstation);
	return status;
}


bool
NtlmContext::IsAnonymous() const
{
	return fUser == NULL || fUser[0] == '\0';
}


status_t
NtlmContext::CreateNegotiate(Packet& out)
{
	out.Reset();
	out.PutBytes(kNtlmSignature, 8);
	out.PutU32(1);
	out.PutU32(kClientFlags);
	put_field(out, 0, 40);	// DomainName
	put_field(out, 0, 40);	// Workstation
	out.PutBytes(kNtlmVersion, 8);
	if (out.Failed())
		return B_NO_MEMORY;

	free(fNegotiateMessage);
	fNegotiateLength = out.Length();
	fNegotiateMessage = (uint8*)malloc(fNegotiateLength);
	if (fNegotiateMessage == NULL)
		return B_NO_MEMORY;
	memcpy(fNegotiateMessage, out.Data(), fNegotiateLength);
	return B_OK;
}


status_t
NtlmContext::ProcessChallenge(const uint8* data, size_t length)
{
	Reader reader(data, length);
	uint8 signature[8];
	uint32 type;
	if (!reader.Bytes(signature, 8) || memcmp(signature, kNtlmSignature, 8) != 0
		|| !reader.U32(type) || type != 2) {
		Log("NTLM: invalid challenge message\n");
		return B_BAD_DATA;
	}

	uint16 targetNameLength, targetNameMaxLength;
	uint32 targetNameOffset;
	reader.U16(targetNameLength);
	reader.U16(targetNameMaxLength);
	reader.U32(targetNameOffset);
	if (!reader.U32(fServerFlags))
		return B_BAD_DATA;
	if (!reader.Bytes(fServerChallenge, 8))
		return B_BAD_DATA;
	if (!reader.Skip(8))
		return B_BAD_DATA;
	uint16 targetInfoLength = 0, targetInfoMaxLength;
	uint32 targetInfoOffset = 0;
	if (fServerFlags & NTLMSSP_NEGOTIATE_TARGET_INFO) {
		reader.U16(targetInfoLength);
		reader.U16(targetInfoMaxLength);
		if (!reader.U32(targetInfoOffset))
			return B_BAD_DATA;
	}

	if (targetNameLength > 0 && (fServerFlags & NTLMSSP_NEGOTIATE_UNICODE) != 0
		&& reader.ValidRange(targetNameOffset, targetNameLength)) {
		Utf16LEToUtf8(data + targetNameOffset, targetNameLength, fTargetName,
			sizeof(fTargetName));
	}

	free(fTargetInfo);
	fTargetInfo = NULL;
	fTargetInfoLength = 0;
	if (targetInfoLength > 0) {
		if (!reader.ValidRange(targetInfoOffset, targetInfoLength))
			return B_BAD_DATA;
		fTargetInfo = (uint8*)malloc(targetInfoLength);
		if (fTargetInfo == NULL)
			return B_NO_MEMORY;
		memcpy(fTargetInfo, data + targetInfoOffset, targetInfoLength);
		fTargetInfoLength = targetInfoLength;
	}

	free(fChallengeMessage);
	fChallengeLength = length;
	fChallengeMessage = (uint8*)malloc(length);
	if (fChallengeMessage == NULL)
		return B_NO_MEMORY;
	memcpy(fChallengeMessage, data, length);

	Trace("NTLM: challenge from '%s', flags 0x%08lx, target info %lu bytes\n",
		fTargetName, (unsigned long)fServerFlags,
		(unsigned long)fTargetInfoLength);
	return B_OK;
}


void
NtlmContext::_ComputeNtowfV2(uint8 out[16])
{
	// NTOWFv2 = HMAC_MD5(MD4(UTF16(password)), UTF16(upper(user) + domain))
	const char* password = fPassword != NULL ? fPassword : "";
	size_t passwordLength = strlen(password);
	ssize_t size = Utf8ToUtf16LE(password, passwordLength, NULL, 0);
	uint8 ntHash[16];
	if (size < 0)
		size = 0;
	uint8* utf16 = (uint8*)malloc(size + 2);
	if (utf16 == NULL) {
		memset(out, 0, 16);
		return;
	}
	Utf8ToUtf16LE(password, passwordLength, utf16, size);
	crypto::md4(utf16, size, ntHash);
	memset(utf16, 0, size);
	free(utf16);

	size_t userLength = strlen(fUser);
	size_t domainLength = fDomain != NULL ? strlen(fDomain) : 0;
	char* identity = (char*)malloc(userLength + domainLength + 1);
	if (identity == NULL) {
		memset(out, 0, 16);
		return;
	}
	memcpy(identity, fUser, userLength);
	identity[userLength] = '\0';
	AsciiToUpper(identity);
	if (domainLength > 0)
		memcpy(identity + userLength, fDomain, domainLength);
	identity[userLength + domainLength] = '\0';

	size_t identityLength = userLength + domainLength;
	size = Utf8ToUtf16LE(identity, identityLength, NULL, 0);
	if (size < 0)
		size = 0;
	utf16 = (uint8*)malloc(size + 2);
	if (utf16 == NULL) {
		free(identity);
		memset(out, 0, 16);
		return;
	}
	Utf8ToUtf16LE(identity, identityLength, utf16, size);
	crypto::hmac_md5(ntHash, 16, utf16, size, out);
	free(utf16);
	free(identity);
	memset(ntHash, 0, sizeof(ntHash));
}


status_t
NtlmContext::CreateAuthenticate(Packet& out, const char* targetHost)
{
	if (fChallengeMessage == NULL)
		return B_NO_INIT;

	out.Reset();
	bool anonymous = IsAnonymous();

	uint32 flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET
		| NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		| NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_VERSION
		| NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;
	if (fServerFlags & NTLMSSP_NEGOTIATE_SIGN)
		flags |= NTLMSSP_NEGOTIATE_SIGN;
	bool keyExchange = (fServerFlags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0;
	if (keyExchange)
		flags |= NTLMSSP_NEGOTIATE_KEY_EXCH;
	if (anonymous)
		flags |= NTLMSSP_ANONYMOUS;

	// Build the NTLMv2 response.
	Packet ntResponse;
	Packet lmResponse;
	uint8 sessionBaseKey[16];
	memset(sessionBaseKey, 0, sizeof(sessionBaseKey));
	bool serverHasTimestamp = false;

	if (anonymous) {
		lmResponse.PutU8(0);
	} else {
		uint8 ntowf[16];
		_ComputeNtowfV2(ntowf);

		uint8 clientChallenge[8];
		RandomBytes(clientChallenge, sizeof(clientChallenge));

		// Walk the server's AV pairs: pick up the timestamp and copy all
		// pairs except EOL (and those we replace).
		uint64 timestamp = 0;
		Packet avPairs;
		Reader reader(fTargetInfo, fTargetInfoLength);
		bool hasFlags = false;
		while (reader.Remaining() >= 4) {
			uint16 id = 0, length = 0;
			reader.U16(id);
			reader.U16(length);
			if (id == MsvAvEOL)
				break;
			if (!reader.HasBytes(length))
				break;
			const uint8* value = reader.Current();
			reader.Skip(length);
			if (id == MsvAvTimestamp && length == 8) {
				timestamp = LoadLE64(value);
				serverHasTimestamp = true;
			}
			if (id == MsvAvFlags && length == 4) {
				hasFlags = true;
				avPairs.PutU16(id);
				avPairs.PutU16(4);
				avPairs.PutU32(LoadLE32(value) | 0x2);
				continue;
			}
			if (id == MsvAvTargetName || id == MsvAvChannelBindings)
				continue;
			avPairs.PutU16(id);
			avPairs.PutU16(length);
			avPairs.PutBytes(value, length);
		}
		if (!hasFlags) {
			avPairs.PutU16(MsvAvFlags);
			avPairs.PutU16(4);
			avPairs.PutU32(0x2);	// MIC present
		}
		// Channel bindings (none)
		avPairs.PutU16(MsvAvChannelBindings);
		avPairs.PutU16(16);
		avPairs.PutZeros(16);
		// Target SPN
		if (targetHost != NULL && targetHost[0] != '\0') {
			size_t hostLength = strlen(targetHost);
			char* spn = (char*)malloc(hostLength + 6);
			if (spn == NULL)
				return B_NO_MEMORY;
			memcpy(spn, "cifs/", 5);
			memcpy(spn + 5, targetHost, hostLength + 1);
			ssize_t spnSize = Utf8ToUtf16LE(spn, hostLength + 5, NULL, 0);
			if (spnSize > 0) {
				avPairs.PutU16(MsvAvTargetName);
				avPairs.PutU16((uint16)spnSize);
				put_utf16(avPairs, spn);
			}
			free(spn);
		}
		avPairs.PutU16(MsvAvEOL);
		avPairs.PutU16(0);
		if (avPairs.Failed())
			return B_NO_MEMORY;

		if (!serverHasTimestamp) {
			// FILETIME: 100ns intervals since 1601-01-01
			timestamp = ((uint64)RealTimeUsecs() + 11644473600000000ULL) * 10;
		}

		Packet temp;
		temp.PutU8(1);
		temp.PutU8(1);
		temp.PutZeros(6);
		temp.PutU64(timestamp);
		temp.PutBytes(clientChallenge, 8);
		temp.PutZeros(4);
		temp.PutBytes(avPairs.Data(), avPairs.Length());
		temp.PutZeros(4);
		if (temp.Failed())
			return B_NO_MEMORY;

		uint8 ntProof[16];
		crypto::HMACMD5 hmac;
		hmac.Init(ntowf, 16);
		hmac.Update(fServerChallenge, 8);
		hmac.Update(temp.Data(), temp.Length());
		hmac.Final(ntProof);

		ntResponse.PutBytes(ntProof, 16);
		ntResponse.PutBytes(temp.Data(), temp.Length());

		if (serverHasTimestamp) {
			lmResponse.PutZeros(24);
		} else {
			uint8 lmProof[16];
			hmac.Init(ntowf, 16);
			hmac.Update(fServerChallenge, 8);
			hmac.Update(clientChallenge, 8);
			hmac.Final(lmProof);
			lmResponse.PutBytes(lmProof, 16);
			lmResponse.PutBytes(clientChallenge, 8);
		}

		crypto::hmac_md5(ntowf, 16, ntProof, 16, sessionBaseKey);
		memset(ntowf, 0, sizeof(ntowf));
	}

	// Session key / key exchange
	uint8 exportedSessionKey[16];
	uint8 encryptedSessionKey[16];
	bool sendEncryptedKey = false;
	if (anonymous) {
		memset(exportedSessionKey, 0, 16);
		fHasSessionKey = false;
	} else if (keyExchange) {
		RandomBytes(exportedSessionKey, 16);
		crypto::rc4(sessionBaseKey, 16, exportedSessionKey, 16,
			encryptedSessionKey);
		sendEncryptedKey = true;
		fHasSessionKey = true;
	} else {
		memcpy(exportedSessionKey, sessionBaseKey, 16);
		fHasSessionKey = true;
	}
	memcpy(fSessionKey, exportedSessionKey, 16);

	// Assemble the AUTHENTICATE_MESSAGE
	const size_t kFixedSize = 88;
	size_t offset = kFixedSize;

	size_t domainSize = fDomain != NULL
		? (size_t)Utf8ToUtf16LE(fDomain, strlen(fDomain), NULL, 0) : 0;
	size_t userSize = !anonymous
		? (size_t)Utf8ToUtf16LE(fUser, strlen(fUser), NULL, 0) : 0;
	size_t workstationSize = fWorkstation != NULL
		? (size_t)Utf8ToUtf16LE(fWorkstation, strlen(fWorkstation), NULL, 0)
		: 0;

	out.PutBytes(kNtlmSignature, 8);
	out.PutU32(3);

	size_t domainOffset = offset;
	offset += domainSize;
	size_t userOffset = offset;
	offset += userSize;
	size_t workstationOffset = offset;
	offset += workstationSize;
	size_t lmOffset = offset;
	offset += lmResponse.Length();
	size_t ntOffset = offset;
	offset += ntResponse.Length();
	size_t keyOffset = offset;

	put_field(out, lmResponse.Length(), lmOffset);
	put_field(out, ntResponse.Length(), ntOffset);
	put_field(out, domainSize, domainOffset);
	put_field(out, userSize, userOffset);
	put_field(out, workstationSize, workstationOffset);
	put_field(out, sendEncryptedKey ? 16 : 0, keyOffset);
	out.PutU32(flags);
	out.PutBytes(kNtlmVersion, 8);
	size_t micOffset = out.Length();
	out.PutZeros(16);

	put_utf16(out, fDomain);
	if (!anonymous)
		put_utf16(out, fUser);
	put_utf16(out, fWorkstation);
	out.PutBytes(lmResponse.Data(), lmResponse.Length());
	out.PutBytes(ntResponse.Data(), ntResponse.Length());
	if (sendEncryptedKey)
		out.PutBytes(encryptedSessionKey, 16);
	if (out.Failed())
		return B_NO_MEMORY;

	if (!anonymous) {
		// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE
		//     || AUTHENTICATE)
		uint8 mic[16];
		crypto::HMACMD5 hmac;
		hmac.Init(exportedSessionKey, 16);
		hmac.Update(fNegotiateMessage, fNegotiateLength);
		hmac.Update(fChallengeMessage, fChallengeLength);
		hmac.Update(out.Data(), out.Length());
		hmac.Final(mic);
		out.SetBytes(micOffset, mic, 16);
	}

	memset(sessionBaseKey, 0, sizeof(sessionBaseKey));
	memset(exportedSessionKey, 0, sizeof(exportedSessionKey));
	return B_OK;
}


}	// namespace smb2
