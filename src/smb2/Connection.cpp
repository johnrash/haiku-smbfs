/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */


#include "Connection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef _KERNEL_MODE
#	include <net/dns_resolver.h>
#endif

#include "Ntlm.h"
#include "NtStatus.h"
#include "Utf.h"


namespace smb2 {


static const uint32 kDesiredCredits = 64;
static const uint32 kMaxCreditRequest = 256;
static const int kMaxFramesPerCall = 32;

static const uint8 kProtocolId[4] = {0xfe, 'S', 'M', 'B'};
static const uint8 kTransformId[4] = {0xfd, 'S', 'M', 'B'};

// FileId placeholder used by related compound operations.
static const FileId kRelatedFileId(0xffffffffffffffffULL,
	0xffffffffffffffffULL);


struct Connection::Request {
	uint16				command;
	uint16				creditCharge;
	Packet				body;

	uint64				messageId;
	uint32				status;
	uint32				flags;
	const uint8*		response;
	size_t				responseLength;
	bool				done;

	Request()
		:
		command(0),
		creditCharge(1),
		messageId(0),
		status(0),
		flags(0),
		response(NULL),
		responseLength(0),
		done(false)
	{
	}
};


struct Connection::Frame {
	uint8*				data;
	size_t				length;
	bool				primary;
};


// #pragma mark - helpers


static int
socket_error()
{
	return errno;
}


static status_t
socket_status()
{
#ifdef __HAIKU__
	status_t error = errno;
	if (error == B_OK)
		error = B_IO_ERROR;
	return error;
#else
	int error = errno;
	if (error == 0)
		return B_IO_ERROR;
	return SMB2_ERRNO(error);
#endif
}


static void
make_guid(uint8 guid[16])
{
	RandomBytes(guid, 16);
	guid[7] = (guid[7] & 0x0f) | 0x40;
	guid[8] = (guid[8] & 0x3f) | 0x80;
}


// #pragma mark - DirectoryIterator


DirectoryIterator::DirectoryIterator(const uint8* buffer, size_t length)
	:
	fBuffer(buffer),
	fLength(length),
	fOffset(0),
	fDone(buffer == NULL || length == 0)
{
}


bool
DirectoryIterator::Next(const uint8** _nameUtf16, size_t* _nameLength,
	FileInfo& info)
{
	if (fDone)
		return false;

	// FileIdFullDirectoryInformation
	const size_t kFixedSize = 80;
	if (fOffset + kFixedSize > fLength) {
		fDone = true;
		return false;
	}

	const uint8* entry = fBuffer + fOffset;
	uint32 nextEntryOffset = LoadLE32(entry);
	info.creationTime = LoadLE64(entry + 8);
	info.lastAccessTime = LoadLE64(entry + 16);
	info.lastWriteTime = LoadLE64(entry + 24);
	info.changeTime = LoadLE64(entry + 32);
	info.endOfFile = LoadLE64(entry + 40);
	info.allocationSize = LoadLE64(entry + 48);
	info.attributes = LoadLE32(entry + 56);
	uint32 nameLength = LoadLE32(entry + 60);
	info.indexNumber = LoadLE64(entry + 72);
	info.numberOfLinks = 1;
	info.deletePending = false;

	if (fOffset + kFixedSize + nameLength > fLength) {
		fDone = true;
		return false;
	}

	*_nameUtf16 = entry + kFixedSize;
	*_nameLength = nameLength;

	if (nextEntryOffset == 0)
		fDone = true;
	else
		fOffset += nextEntryOffset;
	return true;
}


// #pragma mark - Connection


Connection::Connection()
	:
	fLock("smb2 connection"),
	fPort(kDefaultPort),
	fUser(NULL),
	fPassword(NULL),
	fDomain(NULL),
	fWorkstation(NULL),
	fSocket(-1),
	fConnected(false),
	fGeneration(0),
	fDialect(0),
	fServerSecurityMode(0),
	fServerCapabilities(0),
	fMaxTransactSize(65536),
	fMaxReadSize(65536),
	fMaxWriteSize(65536),
	fSupportsMultiCredit(false),
	fCipher(SMB2_ENCRYPTION_NONE),
	fSessionId(0),
	fTreeId(0),
	fSessionFlags(0),
	fShareType(0),
	fShareFlags(0),
	fMaximalAccess(0),
	fNextMessageId(0),
	fCredits(1),
	fSigningEnabled(false),
	fHaveSessionKey(false),
	fEncryptionEnabled(false),
	fNonceCounter(0),
	fPreauthActive(false),
	fReceiveBuffer(NULL),
	fReceiveBufferSize(0),
	fReceiveBufferInUse(false),
	fFrames(NULL),
	fFrameCount(0),
	fFrameCapacity(0)
{
	fHost[0] = '\0';
	fShare[0] = '\0';
	fServerName[0] = '\0';
	memset(fClientGuid, 0, sizeof(fClientGuid));
	memset(fSessionKey, 0, sizeof(fSessionKey));
	memset(fSigningKey, 0, sizeof(fSigningKey));
	memset(fEncryptionKey, 0, sizeof(fEncryptionKey));
	memset(fDecryptionKey, 0, sizeof(fDecryptionKey));
	memset(fNonceRandom, 0, sizeof(fNonceRandom));
	memset(fPreauthHash, 0, sizeof(fPreauthHash));
	crypto::Init();
}


Connection::~Connection()
{
	Disconnect();
	_FreeFrames();
	free(fFrames);
	free(fReceiveBuffer);
	if (fPassword != NULL)
		memset(fPassword, 0, strlen(fPassword));
	free(fUser);
	free(fPassword);
	free(fDomain);
	free(fWorkstation);
	memset(fSessionKey, 0, sizeof(fSessionKey));
	memset(fSigningKey, 0, sizeof(fSigningKey));
	memset(fEncryptionKey, 0, sizeof(fEncryptionKey));
	memset(fDecryptionKey, 0, sizeof(fDecryptionKey));
}


status_t
Connection::Init(const char* host, uint16 port, const char* share,
	const Credentials& credentials, const Options& options)
{
	if (host == NULL || share == NULL)
		return B_BAD_VALUE;
	strlcpy(fHost, host, sizeof(fHost));
	strlcpy(fShare, share, sizeof(fShare));
	fPort = port != 0 ? port : kDefaultPort;
	fOptions = options;

	fUser = strdup(credentials.user != NULL ? credentials.user : "");
	fPassword = strdup(credentials.password != NULL
		? credentials.password : "");
	fDomain = strdup(credentials.domain != NULL ? credentials.domain : "");
	fWorkstation = strdup(credentials.workstation != NULL
		? credentials.workstation : "HAIKU");
	if (fUser == NULL || fPassword == NULL || fDomain == NULL
		|| fWorkstation == NULL) {
		return B_NO_MEMORY;
	}

	fFrameCapacity = kMaxFramesPerCall;
	fFrames = (Frame*)calloc(fFrameCapacity, sizeof(Frame));
	if (fFrames == NULL)
		return B_NO_MEMORY;

	make_guid(fClientGuid);
	RandomBytes(fNonceRandom, sizeof(fNonceRandom));
	return B_OK;
}


status_t
Connection::Connect()
{
	MutexLocker locker(fLock);
	return _EnsureConnected();
}


void
Connection::Disconnect()
{
	MutexLocker locker(fLock);
	_CloseTransport();
}


status_t
Connection::_EnsureConnected()
{
	if (fConnected)
		return B_OK;

	_CloseTransport();

	status_t status = _ConnectTransport();
	if (status != B_OK)
		return status;
	status = _Negotiate();
	if (status == B_OK)
		status = _SessionSetup();
	if (status == B_OK)
		status = _TreeConnect();
	if (status != B_OK) {
		_CloseTransport();
		return status;
	}

	fConnected = true;
	fGeneration++;
	Log("connected to \\\\%s\\%s (dialect 0x%04x, signing %s, "
		"encryption %s)\n", fHost, fShare, fDialect,
		fSigningEnabled ? "on" : "off", fEncryptionEnabled ? "on" : "off");
	return B_OK;
}


status_t
Connection::_ConnectTransport()
{
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(fPort);

	struct sockaddr_storage storage;
	socklen_t addressLength = 0;

	int literal = inet_aton(fHost, &address.sin_addr);
	Trace("inet_aton(\"%s\") = %d\n", fHost, literal);
	if (literal != 0) {
		memcpy(&storage, &address, sizeof(address));
		addressLength = sizeof(address);
	} else {
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		struct addrinfo* result = NULL;
		char service[16];
		snprintf(service, sizeof(service), "%u", fPort);
		int error = getaddrinfo(fHost, service, &hints, &result);
		if (error != 0 || result == NULL) {
			Log("could not resolve host \"%s\" (%d)\n", fHost, error);
			return B_NAME_NOT_FOUND;
		}
		for (struct addrinfo* info = result; info != NULL;
				info = info->ai_next) {
			if (info->ai_addr == NULL)
				continue;
			if (info->ai_family != AF_INET && info->ai_family != AF_INET6)
				continue;
			if (info->ai_addrlen > sizeof(storage))
				continue;
			memcpy(&storage, info->ai_addr, info->ai_addrlen);
			addressLength = info->ai_addrlen;
			if (info->ai_family == AF_INET)
				((struct sockaddr_in*)&storage)->sin_port = htons(fPort);
			else
				((struct sockaddr_in6*)&storage)->sin6_port = htons(fPort);
			break;
		}
		freeaddrinfo(result);
		if (addressLength == 0) {
			Log("no usable address for host \"%s\"\n", fHost);
			return B_NAME_NOT_FOUND;
		}
	}

#ifdef __HAIKU__
	// Haiku's network stack treats an address with sa_len == 0 as empty (and
	// redirects it to loopback). Userland syscalls fill this in, but kernel
	// callers have to do it themselves.
	((struct sockaddr*)&storage)->sa_len = (uint8)addressLength;
#endif

	{
		char addressText[64] = "?";
		uint16 port = 0;
		if (((struct sockaddr*)&storage)->sa_family == AF_INET) {
			inet_ntop(AF_INET, &((struct sockaddr_in*)&storage)->sin_addr,
				addressText, sizeof(addressText));
			port = ntohs(((struct sockaddr_in*)&storage)->sin_port);
		} else if (((struct sockaddr*)&storage)->sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &((struct sockaddr_in6*)&storage)->sin6_addr,
				addressText, sizeof(addressText));
			port = ntohs(((struct sockaddr_in6*)&storage)->sin6_port);
		}
		Trace("connecting to %s port %u (family %u, length %u)\n",
			addressText, port, ((struct sockaddr*)&storage)->sa_family,
			(unsigned)addressLength);
	}

	int fd = socket(((struct sockaddr*)&storage)->sa_family, SOCK_STREAM,
		IPPROTO_TCP);
	if (fd < 0) {
		Log("socket() failed: %d\n", socket_error());
		return socket_status();
	}

	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	struct timeval timeout;
	timeout.tv_sec = (long)(fOptions.timeout / 1000000);
	timeout.tv_usec = (long)(fOptions.timeout % 1000000);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	if (connect(fd, (struct sockaddr*)&storage, addressLength) != 0) {
		status_t status = socket_status();
		Log("connect to %s:%u failed: %d\n", fHost, fPort, socket_error());
		close(fd);
		return status;
	}

	fSocket = fd;
	fNextMessageId = 0;
	fCredits = 1;
	fSessionId = 0;
	fTreeId = 0;
	fSessionFlags = 0;
	fSigningEnabled = false;
	fEncryptionEnabled = false;
	fHaveSessionKey = false;
	fPreauthActive = false;
	fCipher = SMB2_ENCRYPTION_NONE;
	return B_OK;
}


void
Connection::_CloseTransport()
{
	if (fSocket >= 0) {
		shutdown(fSocket, SHUT_RDWR);
		close(fSocket);
		fSocket = -1;
	}
	fConnected = false;
	fSigningEnabled = false;
	fEncryptionEnabled = false;
	fHaveSessionKey = false;
	fSessionId = 0;
	fTreeId = 0;
	memset(fSessionKey, 0, sizeof(fSessionKey));
	memset(fSigningKey, 0, sizeof(fSigningKey));
	memset(fEncryptionKey, 0, sizeof(fEncryptionKey));
	memset(fDecryptionKey, 0, sizeof(fDecryptionKey));
}


// #pragma mark - transport


status_t
Connection::_SendAll(const uint8* data, size_t length)
{
	while (length > 0) {
		ssize_t sent = send(fSocket, data, length, MSG_NOSIGNAL);
		if (sent < 0) {
			int error = socket_error();
			if (error == EINTR)
				continue;
			Log("send failed: %d\n", error);
			return SMB2_DISCONNECTED;
		}
		if (sent == 0)
			return SMB2_DISCONNECTED;
		data += sent;
		length -= sent;
	}
	return B_OK;
}


status_t
Connection::_ReceiveExactly(uint8* buffer, size_t length)
{
	bigtime_t deadline = SystemTime() + fOptions.timeout;
	while (length > 0) {
		struct pollfd pfd;
		pfd.fd = fSocket;
		pfd.events = POLLIN;
		pfd.revents = 0;
		bigtime_t remaining = deadline - SystemTime();
		if (remaining <= 0) {
			Log("timeout waiting for response from %s\n", fHost);
			return B_TIMED_OUT;
		}
		int ready = poll(&pfd, 1, (int)(remaining / 1000) + 1);
		if (ready < 0) {
			int error = socket_error();
			if (error == EINTR)
				continue;
			Log("poll failed: %d\n", error);
			return SMB2_DISCONNECTED;
		}
		if (ready == 0)
			continue;

		ssize_t received = recv(fSocket, buffer, length, 0);
		if (received < 0) {
			int error = socket_error();
			if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK)
				continue;
			Log("recv failed: %d\n", error);
			return SMB2_DISCONNECTED;
		}
		if (received == 0) {
			Log("connection closed by %s\n", fHost);
			return SMB2_DISCONNECTED;
		}
		buffer += received;
		length -= received;
	}
	return B_OK;
}


status_t
Connection::_ReceiveFrame(Frame& frame)
{
	uint8 header[4];
	status_t status = _ReceiveExactly(header, 4);
	if (status != B_OK)
		return status;

	size_t length = ((size_t)header[1] << 16) | ((size_t)header[2] << 8)
		| header[3];
	if (header[0] != 0 || length < 4) {
		Log("invalid transport header\n");
		return B_BAD_DATA;
	}

	uint8* buffer;
	if (!fReceiveBufferInUse) {
		if (length > fReceiveBufferSize) {
			size_t newSize = fReceiveBufferSize == 0 ? 65536
				: fReceiveBufferSize;
			while (newSize < length)
				newSize *= 2;
			uint8* newBuffer = (uint8*)realloc(fReceiveBuffer, newSize);
			if (newBuffer == NULL)
				return B_NO_MEMORY;
			fReceiveBuffer = newBuffer;
			fReceiveBufferSize = newSize;
		}
		buffer = fReceiveBuffer;
		fReceiveBufferInUse = true;
		frame.primary = true;
	} else {
		buffer = (uint8*)malloc(length);
		if (buffer == NULL)
			return B_NO_MEMORY;
		frame.primary = false;
	}

	status = _ReceiveExactly(buffer, length);
	if (status != B_OK) {
		if (!frame.primary)
			free(buffer);
		else
			fReceiveBufferInUse = false;
		return status;
	}

	frame.data = buffer;
	frame.length = length;
	return B_OK;
}


void
Connection::_FreeFrames()
{
	for (int i = 0; i < fFrameCount; i++) {
		if (!fFrames[i].primary)
			free(fFrames[i].data);
	}
	fFrameCount = 0;
	fReceiveBufferInUse = false;
}


// #pragma mark - signing and encryption


void
Connection::_PreauthUpdate(const uint8* data, size_t length)
{
	if (!fPreauthActive)
		return;
	crypto::SHA512 hash;
	hash.Reset();
	hash.Update(fPreauthHash, sizeof(fPreauthHash));
	hash.Update(data, length);
	hash.Final(fPreauthHash);
}


void
Connection::_DeriveKeys()
{
	if (!fHaveSessionKey)
		return;

	if (fDialect >= SMB2_DIALECT_300) {
		if (fDialect == SMB2_DIALECT_311) {
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMBSigningKey", 14,
				fPreauthHash, 64, fSigningKey);
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMBC2SCipherKey", 16,
				fPreauthHash, 64, fEncryptionKey);
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMBS2CCipherKey", 16,
				fPreauthHash, 64, fDecryptionKey);
		} else {
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMB2AESCMAC", 12,
				"SmbSign", 8, fSigningKey);
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMB2AESCCM", 11,
				"ServerIn ", 10, fEncryptionKey);
			crypto::kdf_sp800_108_128(fSessionKey, 16, "SMB2AESCCM", 11,
				"ServerOut", 10, fDecryptionKey);
		}
	} else
		memcpy(fSigningKey, fSessionKey, 16);
}


void
Connection::_SignMessage(uint8* message, size_t length)
{
	if (length < kHeaderSize)
		return;
	uint32 flags = LoadLE32(message + 16) | SMB2_FLAGS_SIGNED;
	StoreLE32(message + 16, flags);
	memset(message + 48, 0, 16);

	if (fDialect >= SMB2_DIALECT_300) {
		fSigningCmac.Init(fSigningKey);
		fSigningCmac.Update(message, length);
		fSigningCmac.Final(message + 48);
	} else {
		uint8 mac[32];
		crypto::hmac_sha256(fSigningKey, 16, message, length, mac);
		memcpy(message + 48, mac, 16);
	}
}


bool
Connection::_VerifyMessage(const uint8* message, size_t length)
{
	if (length < kHeaderSize)
		return false;

	uint8 saved[16];
	memcpy(saved, message + 48, 16);
	uint8* mutableMessage = const_cast<uint8*>(message);
	memset(mutableMessage + 48, 0, 16);

	uint8 computed[32];
	if (fDialect >= SMB2_DIALECT_300) {
		fSigningCmac.Init(fSigningKey);
		fSigningCmac.Update(message, length);
		fSigningCmac.Final(computed);
	} else
		crypto::hmac_sha256(fSigningKey, 16, message, length, computed);

	memcpy(mutableMessage + 48, saved, 16);
	return crypto::secure_equals(saved, computed, 16);
}


status_t
Connection::_EncryptSendBuffer()
{
	// fSendBuffer: 4 byte transport header + plaintext message(s)
	size_t plainLength = fSendBuffer.Length() - 4;
	Packet encrypted;
	if (!encrypted.Reserve(4 + kTransformHeaderSize + plainLength))
		return B_NO_MEMORY;

	uint8* out = encrypted.Grow(4 + kTransformHeaderSize + plainLength);
	if (out == NULL)
		return B_NO_MEMORY;

	size_t frameLength = kTransformHeaderSize + plainLength;
	out[0] = 0;
	out[1] = (uint8)(frameLength >> 16);
	out[2] = (uint8)(frameLength >> 8);
	out[3] = (uint8)frameLength;

	uint8* header = out + 4;
	memset(header, 0, kTransformHeaderSize);
	memcpy(header, kTransformId, 4);
	// nonce
	uint8 nonce[16];
	memset(nonce, 0, sizeof(nonce));
	StoreLE64(nonce, ++fNonceCounter);
	size_t nonceLength = fCipher == SMB2_ENCRYPTION_AES128_GCM ? 12 : 11;
	memcpy(nonce + 8, fNonceRandom, nonceLength - 8);
	memcpy(header + 20, nonce, 16);
	StoreLE32(header + 36, (uint32)plainLength);
	StoreLE16(header + 42, 0x0001);
	StoreLE64(header + 44, fSessionId);

	const uint8* plain = fSendBuffer.Data() + 4;
	uint8* cipher = header + kTransformHeaderSize;
	if (fCipher == SMB2_ENCRYPTION_AES128_GCM) {
		crypto::aes_gcm_encrypt(fEncryptionKey, nonce, header + 20, 32, plain,
			plainLength, cipher, header + 4);
	} else {
		crypto::aes_ccm_encrypt(fEncryptionKey, nonce, header + 20, 32, plain,
			plainLength, cipher, header + 4);
	}

	fSendBuffer.Reset();
	fSendBuffer.PutBytes(encrypted.Data(), encrypted.Length());
	return fSendBuffer.Failed() ? B_NO_MEMORY : B_OK;
}


status_t
Connection::_DecryptFrame(Frame& frame)
{
	if (frame.length < kTransformHeaderSize)
		return B_BAD_DATA;
	uint8* header = frame.data;
	if (LoadLE16(header + 42) != 0x0001) {
		Log("unsupported transform flags\n");
		return B_BAD_DATA;
	}
	uint32 originalSize = LoadLE32(header + 36);
	size_t cipherLength = frame.length - kTransformHeaderSize;
	if (originalSize != cipherLength) {
		Log("transform header size mismatch\n");
		return B_BAD_DATA;
	}
	if (LoadLE64(header + 44) != fSessionId) {
		Log("transform header session mismatch\n");
		return B_BAD_DATA;
	}

	uint8* cipher = header + kTransformHeaderSize;
	bool ok;
	if (fCipher == SMB2_ENCRYPTION_AES128_GCM) {
		ok = crypto::aes_gcm_decrypt(fDecryptionKey, header + 20, header + 20,
			32, cipher, cipherLength, cipher, header + 4);
	} else {
		ok = crypto::aes_ccm_decrypt(fDecryptionKey, header + 20, header + 20,
			32, cipher, cipherLength, cipher, header + 4);
	}
	if (!ok) {
		Log("decryption of server message failed\n");
		return B_BAD_DATA;
	}

	// Drop the transform header.
	memmove(frame.data, cipher, cipherLength);
	frame.length = cipherLength;
	return B_OK;
}


// #pragma mark - request/response


uint16
Connection::_CreditCharge(size_t payload) const
{
	if (!fSupportsMultiCredit)
		return fDialect == SMB2_DIALECT_202 ? 0 : 1;
	if (payload == 0)
		return 1;
	return (uint16)((payload - 1) / 65536 + 1);
}


void
Connection::_FillHeader(uint8* header, const Request& request, uint32 flags,
	uint32 nextCommand)
{
	memset(header, 0, kHeaderSize);
	memcpy(header, kProtocolId, 4);
	StoreLE16(header + 4, 64);
	StoreLE16(header + 6, request.creditCharge);
	StoreLE32(header + 8, 0);
	StoreLE16(header + 12, request.command);

	uint32 creditRequest = request.creditCharge > 0 ? request.creditCharge : 1;
	if ((int32)kDesiredCredits > fCredits)
		creditRequest += kDesiredCredits - fCredits;
	if (creditRequest > kMaxCreditRequest)
		creditRequest = kMaxCreditRequest;
	if (request.command == SMB2_NEGOTIATE)
		creditRequest = 1;
	StoreLE16(header + 14, (uint16)creditRequest);

	StoreLE32(header + 16, flags);
	StoreLE32(header + 20, nextCommand);
	StoreLE64(header + 24, request.messageId);
	StoreLE32(header + 32, 0);
	StoreLE32(header + 36, fTreeId);
	StoreLE64(header + 40, fSessionId);
}


status_t
Connection::_SendReceive(Request* requests, int count)
{
	if (fSocket < 0)
		return SMB2_DISCONNECTED;

	_FreeFrames();

	// Assign message ids and check credits.
	uint32 totalCharge = 0;
	for (int i = 0; i < count; i++) {
		uint16 charge = requests[i].creditCharge;
		if (!fSupportsMultiCredit)
			charge = _CreditCharge(0);
		requests[i].creditCharge = charge;
		totalCharge += charge > 0 ? charge : 1;
	}
	if ((int32)totalCharge > fCredits) {
		Log("insufficient credits (%ld available, %lu needed)\n",
			(long)fCredits, (unsigned long)totalCharge);
		return B_BUSY;
	}

	// Build the frame.
	fSendBuffer.Reset();
	fSendBuffer.PutZeros(4);
	size_t headerOffsets[16];
	if (count > 16)
		return B_BAD_VALUE;

	for (int i = 0; i < count; i++) {
		Request& request = requests[i];
		request.messageId = fNextMessageId;
		fNextMessageId += request.creditCharge > 0 ? request.creditCharge : 1;
		request.done = false;
		request.status = STATUS_INTERNAL_ERROR;
		request.response = NULL;
		request.responseLength = 0;

		// Messages are 8-byte aligned relative to the start of the first
		// SMB2 header, i.e. after the 4 byte transport length prefix.
		while ((fSendBuffer.Length() - 4) % 8 != 0)
			fSendBuffer.PutU8(0);
		headerOffsets[i] = fSendBuffer.Length();
		uint8* header = fSendBuffer.Grow(kHeaderSize);
		if (header == NULL)
			return B_NO_MEMORY;
		uint32 flags = i > 0 ? SMB2_FLAGS_RELATED_OPERATIONS : 0;
		_FillHeader(header, request, flags, 0);
		fSendBuffer.PutBytes(request.body.Data(), request.body.Length());
		if (fSendBuffer.Failed())
			return B_NO_MEMORY;
	}

	// Fix up NextCommand and sign each message.
	for (int i = 0; i < count; i++) {
		size_t start = headerOffsets[i];
		size_t end;
		if (i + 1 < count) {
			// next header is 8-aligned
			end = headerOffsets[i + 1];
			fSendBuffer.SetU32(start + 20, (uint32)(end - start));
		} else
			end = fSendBuffer.Length();

		bool sign = fSigningEnabled && !fEncryptionEnabled;
		if (sign) {
			if (requests[i].command == SMB2_SESSION_SETUP && fTreeId == 0)
				sign = false;
			if (sign)
				_SignMessage(fSendBuffer.Data() + start, end - start);
		}
	}

	// Pre-auth integrity hashing (negotiate / session setup only).
	for (int i = 0; i < count; i++) {
		if (requests[i].command == SMB2_NEGOTIATE
			|| requests[i].command == SMB2_SESSION_SETUP) {
			size_t start = headerOffsets[i];
			size_t end = i + 1 < count ? headerOffsets[i + 1]
				: fSendBuffer.Length();
			_PreauthUpdate(fSendBuffer.Data() + start, end - start);
		}
	}

	if (fEncryptionEnabled) {
		status_t status = _EncryptSendBuffer();
		if (status != B_OK)
			return status;
	} else {
		size_t frameLength = fSendBuffer.Length() - 4;
		if (frameLength > kMaxFrameSize)
			return B_BAD_VALUE;
		uint8* data = fSendBuffer.Data();
		data[0] = 0;
		data[1] = (uint8)(frameLength >> 16);
		data[2] = (uint8)(frameLength >> 8);
		data[3] = (uint8)frameLength;
	}

	status_t status = _SendAll(fSendBuffer.Data(), fSendBuffer.Length());
	if (status != B_OK) {
		_CloseTransport();
		return status;
	}

	// Receive responses until all requests are answered.
	int remaining = count;
	while (remaining > 0) {
		if (fFrameCount >= fFrameCapacity) {
			Log("too many frames in one response\n");
			_CloseTransport();
			return B_BAD_DATA;
		}
		Frame& frame = fFrames[fFrameCount];
		status = _ReceiveFrame(frame);
		if (status != B_OK) {
			_CloseTransport();
			return status;
		}
		fFrameCount++;

		status = _ProcessFrame(frame, requests, count, &remaining);
		if (status != B_OK) {
			_CloseTransport();
			return status;
		}
	}

	return B_OK;
}


status_t
Connection::_ProcessFrame(Frame& frame, Request* requests, int count,
	int* _remaining)
{
	if (frame.length >= 4 && memcmp(frame.data, kTransformId, 4) == 0) {
		if (!fHaveSessionKey || fDialect < SMB2_DIALECT_300) {
			Log("received encrypted message without encryption keys\n");
			return B_BAD_DATA;
		}
		status_t status = _DecryptFrame(frame);
		if (status != B_OK)
			return status;
	}

	size_t offset = 0;
	while (offset + kHeaderSize <= frame.length) {
		const uint8* header = frame.data + offset;
		if (memcmp(header, kProtocolId, 4) != 0) {
			Log("invalid SMB2 response header\n");
			return B_BAD_DATA;
		}

		uint32 status = LoadLE32(header + 8);
		uint16 command = LoadLE16(header + 12);
		uint16 creditResponse = LoadLE16(header + 14);
		uint32 flags = LoadLE32(header + 16);
		uint32 nextCommand = LoadLE32(header + 20);
		uint64 messageId = LoadLE64(header + 24);

		size_t messageLength;
		if (nextCommand != 0) {
			if (nextCommand < kHeaderSize || offset + nextCommand > frame.length) {
				Log("invalid NextCommand in response\n");
				return B_BAD_DATA;
			}
			messageLength = nextCommand;
		} else
			messageLength = frame.length - offset;

		Request* request = NULL;
		for (int i = 0; i < count; i++) {
			if (!requests[i].done && requests[i].messageId == messageId) {
				request = &requests[i];
				break;
			}
		}

		bool interim = (flags & SMB2_FLAGS_ASYNC_COMMAND) != 0
			&& status == STATUS_PENDING;

		if (request != NULL && !interim) {
			// Verify signature when we have signing keys. The session setup
			// response that completes authentication is verified after key
			// derivation by the caller.
			bool verify = fSigningEnabled && (flags & SMB2_FLAGS_SIGNED) != 0;
			if (verify && !_VerifyMessage(header, messageLength)) {
				Log("signature verification failed for command %u\n",
					command);
				return B_BAD_DATA;
			}
			if (fSigningEnabled && (flags & SMB2_FLAGS_SIGNED) == 0
				&& command != SMB2_SESSION_SETUP && !fEncryptionEnabled
				&& fSigningEnabled) {
				Log("unsigned response for command %u rejected\n", command);
				return B_BAD_DATA;
			}

			request->status = status;
			request->flags = flags;
			request->response = header + kHeaderSize;
			request->responseLength = messageLength - kHeaderSize;
			request->done = true;
			(*_remaining)--;

			int32 consumed = request->creditCharge > 0
				? request->creditCharge : 1;
			fCredits += (int32)creditResponse - consumed;
		} else if (request == NULL) {
			if (messageId != 0xffffffffffffffffULL) {
				Trace("unexpected response for message %llu (command %u)\n",
					(unsigned long long)messageId, command);
			}
			if (messageId != 0xffffffffffffffffULL)
				fCredits += creditResponse;
		} else {
			// interim response: credits may be granted here too
			fCredits += creditResponse;
			if (request->creditCharge > 0 && creditResponse > 0) {
				// The final response will not grant again for the charge;
				// nothing to do.
			}
		}

		if (nextCommand == 0)
			break;
		offset += nextCommand;
	}

	return B_OK;
}


// #pragma mark - negotiate / session / tree


status_t
Connection::_Negotiate()
{
	Request request;
	request.command = SMB2_NEGOTIATE;
	request.creditCharge = 0;
	Packet& body = request.body;

	uint16 dialects[5];
	int dialectCount = 0;
	static const uint16 kAllDialects[] = {SMB2_DIALECT_202, SMB2_DIALECT_210,
		SMB2_DIALECT_300, SMB2_DIALECT_302, SMB2_DIALECT_311};
	for (size_t i = 0; i < sizeof(kAllDialects) / sizeof(kAllDialects[0]);
			i++) {
		if (kAllDialects[i] >= fOptions.minDialect
			&& kAllDialects[i] <= fOptions.maxDialect) {
			dialects[dialectCount++] = kAllDialects[i];
		}
	}
	if (dialectCount == 0)
		return B_BAD_VALUE;
	bool offer311 = dialects[dialectCount - 1] == SMB2_DIALECT_311;

	uint16 securityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (fOptions.sign)
		securityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;

	body.PutU16(36);
	body.PutU16((uint16)dialectCount);
	body.PutU16(securityMode);
	body.PutU16(0);
	uint32 capabilities = 0;
	if (dialects[dialectCount - 1] >= SMB2_DIALECT_210)
		capabilities |= SMB2_GLOBAL_CAP_LARGE_MTU;
	if (dialects[dialectCount - 1] >= SMB2_DIALECT_300)
		capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;
	body.PutU32(capabilities);
	body.PutBytes(fClientGuid, 16);
	size_t contextOffsetField = body.Length();
	body.PutU64(0);	// NegotiateContextOffset/Count or ClientStartTime
	for (int i = 0; i < dialectCount; i++)
		body.PutU16(dialects[i]);

	if (offer311) {
		body.Align(8);
		uint32 contextOffset = (uint32)(kHeaderSize + body.Length());
		// SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		body.PutU16(SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
		body.PutU16(38);
		body.PutU32(0);
		body.PutU16(1);
		body.PutU16(32);
		body.PutU16(SMB2_PREAUTH_INTEGRITY_SHA512);
		uint8 salt[32];
		RandomBytes(salt, sizeof(salt));
		body.PutBytes(salt, 32);
		body.Align(8);
		// SMB2_ENCRYPTION_CAPABILITIES
		body.PutU16(SMB2_ENCRYPTION_CAPABILITIES);
		body.PutU16(6);
		body.PutU32(0);
		body.PutU16(2);
		body.PutU16(SMB2_ENCRYPTION_AES128_GCM);
		body.PutU16(SMB2_ENCRYPTION_AES128_CCM);

		body.SetU32(contextOffsetField, contextOffset);
		body.SetU16(contextOffsetField + 4, 2);
		body.SetU16(contextOffsetField + 6, 0);

		// Start pre-auth integrity hashing; it is discarded if the server
		// selects an older dialect.
		memset(fPreauthHash, 0, sizeof(fPreauthHash));
		fPreauthActive = true;
	}
	if (body.Failed())
		return B_NO_MEMORY;

	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status != STATUS_SUCCESS) {
		Log("negotiate failed: %s (0x%08lx)\n", NtStatusName(request.status),
			(unsigned long)request.status);
		return NtStatusToError(request.status);
	}

	Reader reader(request.response, request.responseLength);
	uint16 structureSize, contextCount;
	uint32 contextOffset;
	uint8 serverGuid[16];
	uint64 systemTime, serverStartTime;
	uint16 securityBufferOffset, securityBufferLength;
	if (!reader.U16(structureSize) || structureSize != 65
		|| !reader.U16(fServerSecurityMode) || !reader.U16(fDialect)
		|| !reader.U16(contextCount) || !reader.Bytes(serverGuid, 16)
		|| !reader.U32(fServerCapabilities) || !reader.U32(fMaxTransactSize)
		|| !reader.U32(fMaxReadSize) || !reader.U32(fMaxWriteSize)
		|| !reader.U64(systemTime) || !reader.U64(serverStartTime)
		|| !reader.U16(securityBufferOffset)
		|| !reader.U16(securityBufferLength) || !reader.U32(contextOffset)) {
		Log("malformed negotiate response\n");
		return B_BAD_DATA;
	}

	if (fDialect == SMB2_DIALECT_2XX) {
		Log("server replied with wildcard dialect; multi-protocol "
			"negotiation is not supported\n");
		return B_NOT_SUPPORTED;
	}
	bool known = false;
	for (int i = 0; i < dialectCount; i++) {
		if (dialects[i] == fDialect)
			known = true;
	}
	if (!known) {
		Log("server selected unknown dialect 0x%04x\n", fDialect);
		return B_NOT_SUPPORTED;
	}

	fSupportsMultiCredit = fDialect >= SMB2_DIALECT_210
		&& (fServerCapabilities & SMB2_GLOBAL_CAP_LARGE_MTU) != 0;
	if (!fSupportsMultiCredit) {
		if (fMaxReadSize > 65536)
			fMaxReadSize = 65536;
		if (fMaxWriteSize > 65536)
			fMaxWriteSize = 65536;
		if (fMaxTransactSize > 65536)
			fMaxTransactSize = 65536;
	}
	if (fMaxReadSize > fOptions.maxReadSize)
		fMaxReadSize = fOptions.maxReadSize;
	if (fMaxWriteSize > fOptions.maxWriteSize)
		fMaxWriteSize = fOptions.maxWriteSize;
	if (fMaxTransactSize > 8 * 1024 * 1024)
		fMaxTransactSize = 8 * 1024 * 1024;
	if (fMaxReadSize < 4096 || fMaxWriteSize < 4096
		|| fMaxTransactSize < 4096) {
		Log("server reported unreasonable size limits\n");
		return B_BAD_DATA;
	}

	if (fDialect == SMB2_DIALECT_311) {
		// Parse negotiate contexts.
		bool havePreauth = false;
		fCipher = SMB2_ENCRYPTION_NONE;
		size_t offset = contextOffset;
		if (offset < kHeaderSize)
			return B_BAD_DATA;
		offset -= kHeaderSize;
		for (uint16 i = 0; i < contextCount; i++) {
			offset = (offset + 7) & ~(size_t)7;
			if (!reader.Seek(offset))
				return B_BAD_DATA;
			uint16 type, dataLength;
			uint32 reserved;
			if (!reader.U16(type) || !reader.U16(dataLength)
				|| !reader.U32(reserved) || !reader.HasBytes(dataLength)) {
				return B_BAD_DATA;
			}
			Reader data(reader.Current(), dataLength);
			if (type == SMB2_PREAUTH_INTEGRITY_CAPABILITIES) {
				uint16 hashCount, saltLength, hashId;
				if (data.U16(hashCount) && data.U16(saltLength)
					&& data.U16(hashId) && hashCount == 1
					&& hashId == SMB2_PREAUTH_INTEGRITY_SHA512) {
					havePreauth = true;
				}
			} else if (type == SMB2_ENCRYPTION_CAPABILITIES) {
				uint16 cipherCount, cipher;
				if (data.U16(cipherCount) && cipherCount == 1
					&& data.U16(cipher)) {
					if (cipher == SMB2_ENCRYPTION_AES128_GCM
						|| cipher == SMB2_ENCRYPTION_AES128_CCM) {
						fCipher = cipher;
					}
				}
			}
			offset += 8 + dataLength;
		}
		if (!havePreauth) {
			Log("server did not negotiate pre-authentication integrity\n");
			return B_BAD_DATA;
		}
		// Hash the negotiate response.
		_PreauthUpdate(request.response - kHeaderSize,
			request.responseLength + kHeaderSize);
	} else {
		fPreauthActive = false;
		if (fDialect >= SMB2_DIALECT_300
			&& (fServerCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION) != 0) {
			fCipher = SMB2_ENCRYPTION_AES128_CCM;
		} else
			fCipher = SMB2_ENCRYPTION_NONE;
	}

	Trace("negotiated dialect 0x%04x, security mode 0x%x, caps 0x%08lx, "
		"max read %lu, write %lu, transact %lu, cipher %u\n", fDialect,
		fServerSecurityMode, (unsigned long)fServerCapabilities,
		(unsigned long)fMaxReadSize, (unsigned long)fMaxWriteSize,
		(unsigned long)fMaxTransactSize, fCipher);
	return B_OK;
}


status_t
Connection::_SessionSetup()
{
	NtlmContext* ntlm = new(std::nothrow) NtlmContext;
	if (ntlm == NULL)
		return B_NO_MEMORY;

	status_t status = ntlm->SetCredentials(fUser, fPassword, fDomain,
		fWorkstation);
	if (status != B_OK) {
		delete ntlm;
		return status;
	}

	Packet token;
	status = ntlm->CreateNegotiate(token);
	if (status != B_OK) {
		delete ntlm;
		return status;
	}

	bool serverRequiresSigning
		= (fServerSecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED) != 0;
	uint8 securityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (fOptions.sign)
		securityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;

	const uint8* finalResponseHeader = NULL;
	size_t finalResponseLength = 0;

	for (int round = 0; round < 2; round++) {
		Request request;
		request.command = SMB2_SESSION_SETUP;
		request.creditCharge = 1;
		Packet& body = request.body;
		body.PutU16(25);
		body.PutU8(0);
		body.PutU8(securityMode);
		body.PutU32(0);		// capabilities
		body.PutU32(0);		// channel
		body.PutU16((uint16)(kHeaderSize + 24));
		body.PutU16((uint16)token.Length());
		body.PutU64(0);		// previous session id
		body.PutBytes(token.Data(), token.Length());
		if (body.Failed()) {
			delete ntlm;
			return B_NO_MEMORY;
		}

		status = _SendReceive(&request, 1);
		if (status != B_OK) {
			delete ntlm;
			return status;
		}

		if (request.status != STATUS_SUCCESS
			&& request.status != STATUS_MORE_PROCESSING_REQUIRED) {
			Log("session setup failed: %s (0x%08lx)\n",
				NtStatusName(request.status), (unsigned long)request.status);
			delete ntlm;
			return NtStatusToError(request.status);
		}

		// The session id is assigned with the first response.
		const uint8* header = request.response - kHeaderSize;
		fSessionId = LoadLE64(header + 40);

		Reader reader(request.response, request.responseLength);
		uint16 structureSize, bufferOffset, bufferLength;
		if (!reader.U16(structureSize) || structureSize != 9
			|| !reader.U16(fSessionFlags) || !reader.U16(bufferOffset)
			|| !reader.U16(bufferLength)) {
			delete ntlm;
			return B_BAD_DATA;
		}
		const uint8* blob = NULL;
		if (bufferLength > 0) {
			if (bufferOffset < kHeaderSize || !reader.ValidRange(
					bufferOffset - kHeaderSize, bufferLength)) {
				delete ntlm;
				return B_BAD_DATA;
			}
			blob = request.response + (bufferOffset - kHeaderSize);
		}

		if (request.status == STATUS_MORE_PROCESSING_REQUIRED) {
			if (round == 1 || blob == NULL) {
				delete ntlm;
				return B_BAD_DATA;
			}
			_PreauthUpdate(header, request.responseLength + kHeaderSize);
			status = ntlm->ProcessChallenge(blob, bufferLength);
			if (status == B_OK)
				status = ntlm->CreateAuthenticate(token, fHost);
			if (status != B_OK) {
				delete ntlm;
				return status;
			}
			continue;
		}

		// STATUS_SUCCESS
		finalResponseHeader = header;
		finalResponseLength = request.responseLength + kHeaderSize;
		break;
	}

	if (finalResponseHeader == NULL) {
		delete ntlm;
		return B_ERROR;
	}

	bool guest = (fSessionFlags & (SMB2_SESSION_FLAG_IS_GUEST
		| SMB2_SESSION_FLAG_IS_NULL)) != 0;
	fHaveSessionKey = ntlm->HasSessionKey() && !guest;
	if (fHaveSessionKey)
		memcpy(fSessionKey, ntlm->SessionKey(), 16);
	strlcpy(fServerName, ntlm->TargetName(), sizeof(fServerName));
	delete ntlm;
	fPreauthActive = false;

	_DeriveKeys();

	bool wantSigning = fOptions.sign || serverRequiresSigning
		|| fDialect == SMB2_DIALECT_311;
	if (wantSigning && !fHaveSessionKey) {
		if (fOptions.sign || serverRequiresSigning) {
			Log("signing required but no session key available "
				"(guest/anonymous session)\n");
			return B_PERMISSION_DENIED;
		}
		wantSigning = false;
	}
	fSigningEnabled = wantSigning && fHaveSessionKey;

	// Verify the final session setup response if it was signed.
	uint32 flags = LoadLE32(finalResponseHeader + 16);
	if (fHaveSessionKey && (flags & SMB2_FLAGS_SIGNED) != 0) {
		if (!_VerifyMessage(finalResponseHeader, finalResponseLength)) {
			Log("session setup response signature invalid\n");
			return B_PERMISSION_DENIED;
		}
	} else if (fSigningEnabled && (flags & SMB2_FLAGS_SIGNED) == 0
		&& fDialect == SMB2_DIALECT_311 && !guest) {
		Log("session setup response was not signed\n");
		return B_PERMISSION_DENIED;
	}

	bool wantEncryption = fOptions.seal
		|| (fSessionFlags & SMB2_SESSION_FLAG_ENCRYPT_DATA) != 0;
	if (wantEncryption) {
		if (!fHaveSessionKey || fDialect < SMB2_DIALECT_300
			|| fCipher == SMB2_ENCRYPTION_NONE) {
			Log("encryption required but not available (dialect 0x%04x, "
				"cipher %u)\n", fDialect, fCipher);
			return B_NOT_SUPPORTED;
		}
		fEncryptionEnabled = true;
	}

	Trace("session established (id 0x%llx, flags 0x%x)\n",
		(unsigned long long)fSessionId, fSessionFlags);
	return B_OK;
}


status_t
Connection::_TreeConnect()
{
	Request request;
	request.command = SMB2_TREE_CONNECT;
	request.creditCharge = 1;

	char path[600];
	snprintf(path, sizeof(path), "\\\\%s\\%s", fHost, fShare);
	ssize_t pathSize = Utf8ToUtf16LE(path, strlen(path), NULL, 0);
	if (pathSize < 0)
		return B_BAD_VALUE;

	Packet& body = request.body;
	body.PutU16(9);
	body.PutU16(0);
	body.PutU16((uint16)(kHeaderSize + 8));
	body.PutU16((uint16)pathSize);
	uint8* buffer = body.Grow(pathSize);
	if (buffer == NULL)
		return B_NO_MEMORY;
	Utf8ToUtf16LE(path, strlen(path), buffer, pathSize);

	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status != STATUS_SUCCESS) {
		Log("tree connect to %s failed: %s (0x%08lx)\n", path,
			NtStatusName(request.status), (unsigned long)request.status);
		return NtStatusToError(request.status);
	}

	const uint8* header = request.response - kHeaderSize;
	fTreeId = LoadLE32(header + 36);

	Reader reader(request.response, request.responseLength);
	uint16 structureSize;
	uint8 reserved;
	uint32 capabilities;
	if (!reader.U16(structureSize) || structureSize != 16
		|| !reader.U8(fShareType) || !reader.U8(reserved)
		|| !reader.U32(fShareFlags) || !reader.U32(capabilities)
		|| !reader.U32(fMaximalAccess)) {
		return B_BAD_DATA;
	}

	if (fShareType != SMB2_SHARE_TYPE_DISK) {
		Log("share %s is not a disk share (type %u)\n", path, fShareType);
		return B_NOT_SUPPORTED;
	}

	if ((fShareFlags & SMB2_SHAREFLAG_ENCRYPT_DATA) != 0
		&& !fEncryptionEnabled) {
		if (!fHaveSessionKey || fDialect < SMB2_DIALECT_300
			|| fCipher == SMB2_ENCRYPTION_NONE) {
			Log("share requires encryption but it is not available\n");
			return B_NOT_SUPPORTED;
		}
		fEncryptionEnabled = true;
	}

	Trace("tree connected (id 0x%lx, flags 0x%08lx, access 0x%08lx)\n",
		(unsigned long)fTreeId, (unsigned long)fShareFlags,
		(unsigned long)fMaximalAccess);
	return B_OK;
}


// #pragma mark - request builders


status_t
Connection::_ConvertPath(const char* path, Packet& out)
{
	out.Reset();
	if (path == NULL)
		return B_BAD_VALUE;
	while (*path == '/' || *path == '\\')
		path++;
	size_t length = strlen(path);
	while (length > 0 && (path[length - 1] == '/' || path[length - 1] == '\\'))
		length--;

	ssize_t size = Utf8ToUtf16LE(path, length, NULL, 0);
	if (size < 0)
		return B_BAD_VALUE;
	uint8* buffer = out.Grow(size);
	if (buffer == NULL)
		return B_NO_MEMORY;
	Utf8ToUtf16LE(path, length, buffer, size);

	// Convert separators and collapse duplicate separators.
	size_t write = 0;
	bool lastWasSeparator = false;
	for (ssize_t i = 0; i < size; i += 2) {
		uint16 c = LoadLE16(buffer + i);
		if (c == '/')
			c = '\\';
		if (c == '\\') {
			if (lastWasSeparator)
				continue;
			lastWasSeparator = true;
		} else
			lastWasSeparator = false;
		StoreLE16(buffer + write, c);
		write += 2;
	}
	out.Truncate(write);
	return B_OK;
}


void
Connection::_BuildCreate(Request& request, const Packet& pathUtf16,
	uint32 desiredAccess, uint32 shareAccess, uint32 disposition,
	uint32 createOptions, uint32 attributes)
{
	request.command = SMB2_CREATE;
	request.creditCharge = 1;
	Packet& body = request.body;
	body.Reset();
	body.PutU16(57);
	body.PutU8(0);								// SecurityFlags
	body.PutU8(SMB2_OPLOCK_LEVEL_NONE);
	body.PutU32(SMB2_IMPERSONATION_IMPERSONATION);
	body.PutU64(0);								// SmbCreateFlags
	body.PutU64(0);								// Reserved
	body.PutU32(desiredAccess);
	body.PutU32(attributes);
	body.PutU32(shareAccess);
	body.PutU32(disposition);
	body.PutU32(createOptions);
	body.PutU16((uint16)(kHeaderSize + 56));	// NameOffset
	body.PutU16((uint16)pathUtf16.Length());	// NameLength
	body.PutU32(0);								// CreateContextsOffset
	body.PutU32(0);								// CreateContextsLength
	if (pathUtf16.Length() > 0)
		body.PutBytes(pathUtf16.Data(), pathUtf16.Length());
	else
		body.PutU8(0);
}


void
Connection::_BuildClose(Request& request, const FileId& id)
{
	request.command = SMB2_CLOSE;
	request.creditCharge = 1;
	Packet& body = request.body;
	body.Reset();
	body.PutU16(24);
	body.PutU16(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB);
	body.PutU32(0);
	body.PutU64(id.persistent);
	body.PutU64(id.volatileId);
}


void
Connection::_BuildQueryInfo(Request& request, const FileId& id,
	uint8 infoType, uint8 infoClass, uint32 additional, uint32 outputLength)
{
	request.command = SMB2_QUERY_INFO;
	request.creditCharge = _CreditCharge(outputLength);
	Packet& body = request.body;
	body.Reset();
	body.PutU16(41);
	body.PutU8(infoType);
	body.PutU8(infoClass);
	body.PutU32(outputLength);
	body.PutU16(0);			// InputBufferOffset
	body.PutU16(0);			// Reserved
	body.PutU32(0);			// InputBufferLength
	body.PutU32(additional);
	body.PutU32(0);			// Flags
	body.PutU64(id.persistent);
	body.PutU64(id.volatileId);
	body.PutU8(0);			// Buffer
}


void
Connection::_BuildSetInfo(Request& request, const FileId& id, uint8 infoType,
	uint8 infoClass, const void* data, size_t length)
{
	request.command = SMB2_SET_INFO;
	request.creditCharge = _CreditCharge(length);
	Packet& body = request.body;
	body.Reset();
	body.PutU16(33);
	body.PutU8(infoType);
	body.PutU8(infoClass);
	body.PutU32((uint32)length);
	body.PutU16((uint16)(kHeaderSize + 32));
	body.PutU16(0);
	body.PutU32(0);			// AdditionalInformation
	body.PutU64(id.persistent);
	body.PutU64(id.volatileId);
	body.PutBytes(data, length);
}


status_t
Connection::_ParseFileInfoFromCreate(const uint8* data, FileInfo& info)
{
	// data points at CreationTime of the CREATE/CLOSE response layout:
	// CreationTime, LastAccessTime, LastWriteTime, ChangeTime,
	// AllocationSize, EndofFile, FileAttributes
	info.creationTime = LoadLE64(data);
	info.lastAccessTime = LoadLE64(data + 8);
	info.lastWriteTime = LoadLE64(data + 16);
	info.changeTime = LoadLE64(data + 24);
	info.allocationSize = LoadLE64(data + 32);
	info.endOfFile = LoadLE64(data + 40);
	info.attributes = LoadLE32(data + 48);
	return B_OK;
}


status_t
Connection::_ParseCreateResponse(const Request& request, FileId& id,
	FileInfo* info, uint32* _createAction)
{
	if (request.responseLength < 88)
		return B_BAD_DATA;
	const uint8* r = request.response;
	if (LoadLE16(r) != 89)
		return B_BAD_DATA;
	if (_createAction != NULL)
		*_createAction = LoadLE32(r + 4);
	if (info != NULL) {
		_ParseFileInfoFromCreate(r + 8, *info);
		info->numberOfLinks = 1;
		info->deletePending = false;
		info->indexNumber = 0;
	}
	id.persistent = LoadLE64(r + 64);
	id.volatileId = LoadLE64(r + 72);
	return B_OK;
}


status_t
Connection::_ParseQueryInfoResponse(const Request& request,
	const uint8** _data, size_t* _length)
{
	Reader reader(request.response, request.responseLength);
	uint16 structureSize, offset;
	uint32 length;
	if (!reader.U16(structureSize) || structureSize != 9
		|| !reader.U16(offset) || !reader.U32(length)) {
		return B_BAD_DATA;
	}
	if (length == 0) {
		*_data = NULL;
		*_length = 0;
		return B_OK;
	}
	if (offset < kHeaderSize
		|| !reader.ValidRange(offset - kHeaderSize, length)) {
		return B_BAD_DATA;
	}
	*_data = request.response + (offset - kHeaderSize);
	*_length = length;
	return B_OK;
}


status_t
Connection::ParseAllInformation(const uint8* data, size_t length,
	FileInfo& info)
{
	if (length < 96)
		return B_BAD_DATA;
	info.creationTime = LoadLE64(data);
	info.lastAccessTime = LoadLE64(data + 8);
	info.lastWriteTime = LoadLE64(data + 16);
	info.changeTime = LoadLE64(data + 24);
	info.attributes = LoadLE32(data + 32);
	info.allocationSize = LoadLE64(data + 40);
	info.endOfFile = LoadLE64(data + 48);
	info.numberOfLinks = LoadLE32(data + 56);
	info.deletePending = data[60] != 0;
	info.indexNumber = LoadLE64(data + 64);
	return B_OK;
}


// #pragma mark - public operations


status_t
Connection::Create(const char* path, uint32 desiredAccess, uint32 shareAccess,
	uint32 disposition, uint32 createOptions, uint32 attributes, FileId& id,
	FileInfo* info, uint32* _createAction)
{
	MutexLocker locker(fLock);
	status_t status = _EnsureConnected();
	if (status != B_OK)
		return status;

	Packet pathUtf16;
	status = _ConvertPath(path, pathUtf16);
	if (status != B_OK)
		return status;

	Request request;
	_BuildCreate(request, pathUtf16, desiredAccess, shareAccess, disposition,
		createOptions, attributes);
	if (request.body.Failed())
		return B_NO_MEMORY;

	status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status != STATUS_SUCCESS) {
		Trace("create \"%s\" failed: %s\n", path, NtStatusName(request.status));
		return NtStatusToError(request.status);
	}
	return _ParseCreateResponse(request, id, info, _createAction);
}


status_t
Connection::Close(const FileId& id, FileInfo* info)
{
	MutexLocker locker(fLock);
	if (!fConnected)
		return SMB2_DISCONNECTED;

	Request request;
	_BuildClose(request, id);
	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status != STATUS_SUCCESS)
		return NtStatusToError(request.status);
	if (info != NULL && request.responseLength >= 60
		&& LoadLE16(request.response) == 60) {
		_ParseFileInfoFromCreate(request.response + 8, *info);
	}
	return B_OK;
}


status_t
Connection::Read(const FileId& id, uint64 offset, void* _buffer, size_t length,
	size_t* _bytesRead)
{
	MutexLocker locker(fLock);
	uint8* buffer = (uint8*)_buffer;
	*_bytesRead = 0;

	if (!fConnected)
		return SMB2_DISCONNECTED;

	while (length > 0) {
		size_t chunk = length;
		if (chunk > fMaxReadSize)
			chunk = fMaxReadSize;
		if (fSupportsMultiCredit) {
			size_t creditLimit = (size_t)(fCredits > 0 ? fCredits : 1) * 65536;
			if (chunk > creditLimit)
				chunk = creditLimit;
		} else if (chunk > 65536)
			chunk = 65536;

		Request request;
		request.command = SMB2_READ;
		request.creditCharge = _CreditCharge(chunk);
		Packet& body = request.body;
		body.PutU16(49);
		body.PutU8(0x50);
		body.PutU8(0);
		body.PutU32((uint32)chunk);
		body.PutU64(offset);
		body.PutU64(id.persistent);
		body.PutU64(id.volatileId);
		body.PutU32(0);					// MinimumCount
		body.PutU32(0);					// Channel
		body.PutU32((uint32)(length - chunk));	// RemainingBytes
		body.PutU16(0);
		body.PutU16(0);
		body.PutU8(0);
		if (body.Failed())
			return B_NO_MEMORY;

		status_t status = _SendReceive(&request, 1);
		if (status != B_OK)
			return *_bytesRead > 0 ? B_OK : status;

		if (request.status == STATUS_END_OF_FILE)
			break;
		if (request.status != STATUS_SUCCESS
			&& request.status != STATUS_BUFFER_OVERFLOW) {
			return *_bytesRead > 0 ? B_OK : NtStatusToError(request.status);
		}

		Reader reader(request.response, request.responseLength);
		uint16 structureSize;
		uint8 dataOffset, reserved;
		uint32 dataLength, dataRemaining;
		if (!reader.U16(structureSize) || structureSize != 17
			|| !reader.U8(dataOffset) || !reader.U8(reserved)
			|| !reader.U32(dataLength) || !reader.U32(dataRemaining)) {
			return B_BAD_DATA;
		}
		if (dataLength == 0)
			break;
		if (dataOffset < kHeaderSize
			|| !reader.ValidRange(dataOffset - kHeaderSize, dataLength)
			|| dataLength > chunk) {
			return B_BAD_DATA;
		}
		memcpy(buffer, request.response + (dataOffset - kHeaderSize),
			dataLength);
		buffer += dataLength;
		offset += dataLength;
		length -= dataLength;
		*_bytesRead += dataLength;
		if (dataLength < chunk)
			break;
	}
	return B_OK;
}


status_t
Connection::Write(const FileId& id, uint64 offset, const void* _buffer,
	size_t length, size_t* _bytesWritten)
{
	MutexLocker locker(fLock);
	const uint8* buffer = (const uint8*)_buffer;
	*_bytesWritten = 0;

	if (!fConnected)
		return SMB2_DISCONNECTED;

	while (length > 0) {
		size_t chunk = length;
		if (chunk > fMaxWriteSize)
			chunk = fMaxWriteSize;
		if (fSupportsMultiCredit) {
			size_t creditLimit = (size_t)(fCredits > 0 ? fCredits : 1) * 65536;
			if (chunk > creditLimit)
				chunk = creditLimit;
		} else if (chunk > 65536)
			chunk = 65536;

		Request request;
		request.command = SMB2_WRITE;
		request.creditCharge = _CreditCharge(chunk);
		Packet& body = request.body;
		body.PutU16(49);
		body.PutU16((uint16)(kHeaderSize + 48));	// DataOffset
		body.PutU32((uint32)chunk);
		body.PutU64(offset);
		body.PutU64(id.persistent);
		body.PutU64(id.volatileId);
		body.PutU32(0);					// Channel
		body.PutU32((uint32)(length - chunk));	// RemainingBytes
		body.PutU16(0);
		body.PutU16(0);
		body.PutU32(0);					// Flags
		body.PutBytes(buffer, chunk);
		if (body.Failed())
			return B_NO_MEMORY;

		status_t status = _SendReceive(&request, 1);
		if (status != B_OK)
			return *_bytesWritten > 0 ? B_OK : status;
		if (request.status != STATUS_SUCCESS)
			return *_bytesWritten > 0 ? B_OK : NtStatusToError(request.status);

		Reader reader(request.response, request.responseLength);
		uint16 structureSize, reserved;
		uint32 count;
		if (!reader.U16(structureSize) || structureSize != 17
			|| !reader.U16(reserved) || !reader.U32(count)) {
			return B_BAD_DATA;
		}
		if (count > chunk)
			count = (uint32)chunk;
		buffer += count;
		offset += count;
		length -= count;
		*_bytesWritten += count;
		if (count == 0)
			break;
	}
	return B_OK;
}


status_t
Connection::Flush(const FileId& id)
{
	MutexLocker locker(fLock);
	if (!fConnected)
		return SMB2_DISCONNECTED;

	Request request;
	request.command = SMB2_FLUSH;
	request.creditCharge = 1;
	Packet& body = request.body;
	body.PutU16(24);
	body.PutU16(0);
	body.PutU32(0);
	body.PutU64(id.persistent);
	body.PutU64(id.volatileId);

	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	return NtStatusToError(request.status);
}


status_t
Connection::QueryInfo(const FileId& id, uint8 infoType, uint8 infoClass,
	uint32 additional, void* buffer, size_t bufferSize, size_t* _resultSize)
{
	MutexLocker locker(fLock);
	if (!fConnected)
		return SMB2_DISCONNECTED;
	if (bufferSize > fMaxTransactSize)
		bufferSize = fMaxTransactSize;

	Request request;
	_BuildQueryInfo(request, id, infoType, infoClass, additional,
		(uint32)bufferSize);
	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status != STATUS_SUCCESS
		&& request.status != STATUS_BUFFER_OVERFLOW) {
		return NtStatusToError(request.status);
	}

	const uint8* data;
	size_t length;
	status = _ParseQueryInfoResponse(request, &data, &length);
	if (status != B_OK)
		return status;
	if (length > bufferSize)
		length = bufferSize;
	if (length > 0)
		memcpy(buffer, data, length);
	*_resultSize = length;
	return B_OK;
}


status_t
Connection::SetInfo(const FileId& id, uint8 infoType, uint8 infoClass,
	const void* data, size_t length)
{
	MutexLocker locker(fLock);
	if (!fConnected)
		return SMB2_DISCONNECTED;

	Request request;
	_BuildSetInfo(request, id, infoType, infoClass, data, length);
	if (request.body.Failed())
		return B_NO_MEMORY;
	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	return NtStatusToError(request.status);
}


status_t
Connection::QueryDirectory(const FileId& id, const char* pattern, uint8 flags,
	void* buffer, size_t bufferSize, size_t* _resultSize)
{
	MutexLocker locker(fLock);
	*_resultSize = 0;
	if (!fConnected)
		return SMB2_DISCONNECTED;
	if (bufferSize > fMaxTransactSize)
		bufferSize = fMaxTransactSize;
	if (fSupportsMultiCredit) {
		size_t creditLimit = (size_t)(fCredits > 0 ? fCredits : 1) * 65536;
		if (bufferSize > creditLimit)
			bufferSize = creditLimit;
	} else if (bufferSize > 65536)
		bufferSize = 65536;

	if (pattern == NULL || pattern[0] == '\0')
		pattern = "*";
	ssize_t patternSize = Utf8ToUtf16LE(pattern, strlen(pattern), NULL, 0);
	if (patternSize < 0)
		return B_BAD_VALUE;

	Request request;
	request.command = SMB2_QUERY_DIRECTORY;
	request.creditCharge = _CreditCharge(bufferSize);
	Packet& body = request.body;
	body.PutU16(33);
	body.PutU8(FileIdFullDirectoryInformation);
	body.PutU8(flags);
	body.PutU32(0);				// FileIndex
	body.PutU64(id.persistent);
	body.PutU64(id.volatileId);
	body.PutU16((uint16)(kHeaderSize + 32));
	body.PutU16((uint16)patternSize);
	body.PutU32((uint32)bufferSize);
	uint8* nameBuffer = body.Grow(patternSize);
	if (nameBuffer == NULL)
		return B_NO_MEMORY;
	Utf8ToUtf16LE(pattern, strlen(pattern), nameBuffer, patternSize);

	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	if (request.status == STATUS_NO_MORE_FILES
		|| request.status == STATUS_NO_SUCH_FILE) {
		return B_ENTRY_NOT_FOUND;
	}
	if (request.status != STATUS_SUCCESS)
		return NtStatusToError(request.status);

	const uint8* data;
	size_t length;
	status = _ParseQueryInfoResponse(request, &data, &length);
	if (status != B_OK)
		return status;
	if (length > bufferSize)
		return B_BAD_DATA;
	if (length > 0)
		memcpy(buffer, data, length);
	*_resultSize = length;
	return B_OK;
}


status_t
Connection::Echo()
{
	MutexLocker locker(fLock);
	if (!fConnected)
		return SMB2_DISCONNECTED;

	Request request;
	request.command = SMB2_ECHO;
	request.creditCharge = 1;
	request.body.PutU16(4);
	request.body.PutU16(0);
	status_t status = _SendReceive(&request, 1);
	if (status != B_OK)
		return status;
	return NtStatusToError(request.status);
}


// #pragma mark - convenience


status_t
Connection::QueryFileInfo(const FileId& id, FileInfo& info)
{
	uint8 buffer[1024];
	size_t length;
	status_t status = QueryInfo(id, SMB2_0_INFO_FILE, FileAllInformation, 0,
		buffer, sizeof(buffer), &length);
	if (status != B_OK)
		return status;
	return ParseAllInformation(buffer, length, info);
}


status_t
Connection::SetEndOfFile(const FileId& id, uint64 size)
{
	uint8 data[8];
	StoreLE64(data, size);
	return SetInfo(id, SMB2_0_INFO_FILE, FileEndOfFileInformation, data, 8);
}


status_t
Connection::SetBasicInfo(const FileId& id, uint64 creationTime,
	uint64 lastAccessTime, uint64 lastWriteTime, uint64 changeTime,
	uint32 attributes)
{
	uint8 data[40];
	StoreLE64(data, creationTime);
	StoreLE64(data + 8, lastAccessTime);
	StoreLE64(data + 16, lastWriteTime);
	StoreLE64(data + 24, changeTime);
	StoreLE32(data + 32, attributes);
	StoreLE32(data + 36, 0);
	return SetInfo(id, SMB2_0_INFO_FILE, FileBasicInformation, data, 40);
}


status_t
Connection::SetDisposition(const FileId& id, bool deleteOnClose)
{
	uint8 data = deleteOnClose ? 1 : 0;
	return SetInfo(id, SMB2_0_INFO_FILE, FileDispositionInformation, &data, 1);
}


status_t
Connection::Rename(const FileId& id, const char* newPath, bool replace)
{
	Packet pathUtf16;
	{
		MutexLocker locker(fLock);
		status_t status = _ConvertPath(newPath, pathUtf16);
		if (status != B_OK)
			return status;
	}
	Packet data;
	data.PutU8(replace ? 1 : 0);
	data.PutZeros(7);
	data.PutU64(0);
	data.PutU32((uint32)pathUtf16.Length());
	data.PutBytes(pathUtf16.Data(), pathUtf16.Length());
	if (data.Failed())
		return B_NO_MEMORY;
	return SetInfo(id, SMB2_0_INFO_FILE, FileRenameInformation, data.Data(),
		data.Length());
}


// #pragma mark - compound path operations


status_t
Connection::QueryPathInfo(const char* path, FileInfo& info)
{
	MutexLocker locker(fLock);
	status_t status = _EnsureConnected();
	if (status != B_OK)
		return status;

	Packet pathUtf16;
	status = _ConvertPath(path, pathUtf16);
	if (status != B_OK)
		return status;

	Request requests[3];
	_BuildCreate(requests[0], pathUtf16, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL,
		FILE_OPEN, 0, 0);
	_BuildQueryInfo(requests[1], kRelatedFileId, SMB2_0_INFO_FILE,
		FileAllInformation, 0, 1024);
	_BuildClose(requests[2], kRelatedFileId);
	for (int i = 0; i < 3; i++) {
		if (requests[i].body.Failed())
			return B_NO_MEMORY;
	}

	status = _SendReceive(requests, 3);
	if (status != B_OK)
		return status;
	if (requests[0].status != STATUS_SUCCESS) {
		Trace("query path info \"%s\": %s\n", path,
			NtStatusName(requests[0].status));
		return NtStatusToError(requests[0].status);
	}
	if (requests[1].status != STATUS_SUCCESS
		&& requests[1].status != STATUS_BUFFER_OVERFLOW) {
		return NtStatusToError(requests[1].status);
	}

	const uint8* data;
	size_t length;
	status = _ParseQueryInfoResponse(requests[1], &data, &length);
	if (status != B_OK)
		return status;
	return ParseAllInformation(data, length, info);
}


status_t
Connection::QueryFsInfo(FsInfo& info)
{
	MutexLocker locker(fLock);
	status_t status = _EnsureConnected();
	if (status != B_OK)
		return status;

	Packet pathUtf16;
	status = _ConvertPath("", pathUtf16);
	if (status != B_OK)
		return status;

	Request requests[4];
	_BuildCreate(requests[0], pathUtf16, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL,
		FILE_OPEN, FILE_DIRECTORY_FILE, 0);
	_BuildQueryInfo(requests[1], kRelatedFileId, SMB2_0_INFO_FILESYSTEM,
		FileFsSizeInformation, 0, 24);
	_BuildQueryInfo(requests[2], kRelatedFileId, SMB2_0_INFO_FILESYSTEM,
		FileFsAttributeInformation, 0, 256);
	_BuildClose(requests[3], kRelatedFileId);
	for (int i = 0; i < 4; i++) {
		if (requests[i].body.Failed())
			return B_NO_MEMORY;
	}

	status = _SendReceive(requests, 4);
	if (status != B_OK)
		return status;
	if (requests[0].status != STATUS_SUCCESS)
		return NtStatusToError(requests[0].status);

	memset(&info, 0, sizeof(info));
	if (requests[1].status == STATUS_SUCCESS
		|| requests[1].status == STATUS_BUFFER_OVERFLOW) {
		const uint8* data;
		size_t length;
		if (_ParseQueryInfoResponse(requests[1], &data, &length) == B_OK
			&& length >= 24) {
			info.totalUnits = LoadLE64(data);
			info.availableUnits = LoadLE64(data + 8);
			info.sectorsPerUnit = LoadLE32(data + 16);
			info.bytesPerSector = LoadLE32(data + 20);
		}
	}
	if (requests[2].status == STATUS_SUCCESS
		|| requests[2].status == STATUS_BUFFER_OVERFLOW) {
		const uint8* data;
		size_t length;
		if (_ParseQueryInfoResponse(requests[2], &data, &length) == B_OK
			&& length >= 12) {
			info.attributes = LoadLE32(data);
			info.maxComponentLength = LoadLE32(data + 4);
			uint32 nameLength = LoadLE32(data + 8);
			if (nameLength <= length - 12) {
				Utf16LEToUtf8(data + 12, nameLength, info.fsName,
					sizeof(info.fsName));
			}
		}
	}
	return B_OK;
}


status_t
Connection::_OpenSetClose(const char* path, uint32 desiredAccess,
	uint32 createOptions, uint8 infoClass, const void* data, size_t length)
{
	MutexLocker locker(fLock);
	status_t status = _EnsureConnected();
	if (status != B_OK)
		return status;

	Packet pathUtf16;
	status = _ConvertPath(path, pathUtf16);
	if (status != B_OK)
		return status;

	Request requests[3];
	_BuildCreate(requests[0], pathUtf16, desiredAccess, FILE_SHARE_ALL,
		FILE_OPEN, createOptions, 0);
	_BuildSetInfo(requests[1], kRelatedFileId, SMB2_0_INFO_FILE, infoClass,
		data, length);
	_BuildClose(requests[2], kRelatedFileId);
	for (int i = 0; i < 3; i++) {
		if (requests[i].body.Failed())
			return B_NO_MEMORY;
	}

	status = _SendReceive(requests, 3);
	if (status != B_OK)
		return status;
	if (requests[0].status != STATUS_SUCCESS)
		return NtStatusToError(requests[0].status);
	if (requests[1].status != STATUS_SUCCESS)
		return NtStatusToError(requests[1].status);
	return B_OK;
}


status_t
Connection::DeletePath(const char* path, bool directory)
{
	uint8 data = 1;
	return _OpenSetClose(path, DELETE_ACCESS,
		directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE,
		FileDispositionInformation, &data, 1);
}


status_t
Connection::RenamePath(const char* from, const char* to, bool replace)
{
	Packet pathUtf16;
	{
		MutexLocker locker(fLock);
		status_t status = _ConvertPath(to, pathUtf16);
		if (status != B_OK)
			return status;
	}
	Packet data;
	data.PutU8(replace ? 1 : 0);
	data.PutZeros(7);
	data.PutU64(0);
	data.PutU32((uint32)pathUtf16.Length());
	data.PutBytes(pathUtf16.Data(), pathUtf16.Length());
	if (data.Failed())
		return B_NO_MEMORY;
	return _OpenSetClose(from, DELETE_ACCESS, 0, FileRenameInformation,
		data.Data(), data.Length());
}


status_t
Connection::SetPathBasicInfo(const char* path, uint64 creationTime,
	uint64 lastAccessTime, uint64 lastWriteTime, uint64 changeTime,
	uint32 attributes)
{
	uint8 data[40];
	StoreLE64(data, creationTime);
	StoreLE64(data + 8, lastAccessTime);
	StoreLE64(data + 16, lastWriteTime);
	StoreLE64(data + 24, changeTime);
	StoreLE32(data + 32, attributes);
	StoreLE32(data + 36, 0);
	return _OpenSetClose(path, FILE_WRITE_ATTRIBUTES, 0, FileBasicInformation,
		data, 40);
}


status_t
Connection::SetPathEndOfFile(const char* path, uint64 size)
{
	uint8 data[8];
	StoreLE64(data, size);
	return _OpenSetClose(path, FILE_WRITE_DATA, FILE_NON_DIRECTORY_FILE,
		FileEndOfFileInformation, data, 8);
}


status_t
Connection::CreateDirectoryPath(const char* path, FileInfo* info)
{
	MutexLocker locker(fLock);
	status_t status = _EnsureConnected();
	if (status != B_OK)
		return status;

	Packet pathUtf16;
	status = _ConvertPath(path, pathUtf16);
	if (status != B_OK)
		return status;

	Request requests[2];
	_BuildCreate(requests[0], pathUtf16, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL,
		FILE_CREATE, FILE_DIRECTORY_FILE, FILE_ATTRIBUTE_DIRECTORY);
	_BuildClose(requests[1], kRelatedFileId);
	for (int i = 0; i < 2; i++) {
		if (requests[i].body.Failed())
			return B_NO_MEMORY;
	}

	status = _SendReceive(requests, 2);
	if (status != B_OK)
		return status;
	if (requests[0].status != STATUS_SUCCESS)
		return NtStatusToError(requests[0].status);

	if (info != NULL) {
		FileId id;
		_ParseCreateResponse(requests[0], id, info, NULL);
	}
	return B_OK;
}


}	// namespace smb2
