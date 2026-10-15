/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * SMB2/3 client connection: one TCP connection carrying one session and
 * one tree connect. Requests are processed synchronously under a lock.
 */
#ifndef SMB2_CONNECTION_H
#define SMB2_CONNECTION_H

#include "Buffer.h"
#include "Crypto.h"
#include "Platform.h"
#include "Smb2Defs.h"
#include "Types.h"

#include <time.h>


namespace smb2 {


class NtlmContext;


struct FileId {
	uint64				persistent;
	uint64				volatileId;

	FileId() : persistent(0), volatileId(0) {}
	constexpr FileId(uint64 p, uint64 v) : persistent(p), volatileId(v) {}
	bool IsValid() const { return persistent != 0 || volatileId != 0; }
	void Invalidate() { persistent = 0; volatileId = 0; }
};


struct FileInfo {
	uint64				creationTime;		// FILETIME
	uint64				lastAccessTime;
	uint64				lastWriteTime;
	uint64				changeTime;
	uint64				allocationSize;
	uint64				endOfFile;
	uint32				attributes;
	uint32				numberOfLinks;
	uint64				indexNumber;
	bool				deletePending;

	FileInfo()
		:
		creationTime(0), lastAccessTime(0), lastWriteTime(0), changeTime(0),
		allocationSize(0), endOfFile(0), attributes(0), numberOfLinks(1),
		indexNumber(0), deletePending(false)
	{
	}

	bool IsDirectory() const
		{ return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0; }
	bool IsReadOnly() const
		{ return (attributes & FILE_ATTRIBUTE_READONLY) != 0; }
};


struct FsInfo {
	uint64				totalUnits;
	uint64				availableUnits;
	uint32				sectorsPerUnit;
	uint32				bytesPerSector;
	uint32				attributes;
	uint32				maxComponentLength;
	char				fsName[32];
};


struct Credentials {
	const char*			user;
	const char*			password;
	const char*			domain;
	const char*			workstation;

	Credentials() : user(NULL), password(NULL), domain(NULL), workstation(NULL) {}
};


struct Options {
	uint16				minDialect;
	uint16				maxDialect;
	bool				sign;			// require message signing
	bool				seal;			// require encryption
	bigtime_t			timeout;		// per request, microseconds
	uint32				maxReadSize;	// upper bound for a single READ
	uint32				maxWriteSize;

	Options()
		:
		minDialect(SMB2_DIALECT_202),
		maxDialect(SMB2_DIALECT_311),
		sign(false),
		seal(false),
		timeout(30 * 1000000LL),
		maxReadSize(1024 * 1024),
		maxWriteSize(1024 * 1024)
	{
	}
};


// FILETIME (100 ns intervals since 1601-01-01) conversion helpers.
static const uint64 kFileTimeUnixEpoch = 116444736000000000ULL;

static inline void
FileTimeToTimespec(uint64 fileTime, struct timespec& spec)
{
	if (fileTime < kFileTimeUnixEpoch) {
		spec.tv_sec = 0;
		spec.tv_nsec = 0;
		return;
	}
	uint64 unix100ns = fileTime - kFileTimeUnixEpoch;
	spec.tv_sec = (time_t)(unix100ns / 10000000ULL);
	spec.tv_nsec = (long)((unix100ns % 10000000ULL) * 100);
}


static inline uint64
TimespecToFileTime(const struct timespec& spec)
{
	return (uint64)spec.tv_sec * 10000000ULL + (uint64)spec.tv_nsec / 100
		+ kFileTimeUnixEpoch;
}


// Iterates over FileIdFullDirectoryInformation entries.
class DirectoryIterator {
public:
								DirectoryIterator(const uint8* buffer,
									size_t length);

			bool				Next(const uint8** _nameUtf16,
									size_t* _nameLength, FileInfo& info);

private:
			const uint8*		fBuffer;
			size_t				fLength;
			size_t				fOffset;
			bool				fDone;
};


class Connection {
public:
								Connection();
								~Connection();

			status_t			Init(const char* host, uint16 port,
									const char* share,
									const Credentials& credentials,
									const Options& options);

			status_t			Connect();
			void				Disconnect();
			bool				IsConnected() const { return fConnected; }
			uint32				Generation() const { return fGeneration; }

			uint16				Dialect() const { return fDialect; }
			uint32				MaxReadSize() const { return fMaxReadSize; }
			uint32				MaxWriteSize() const { return fMaxWriteSize; }
			uint32				MaxTransactSize() const
									{ return fMaxTransactSize; }
			bool				IsSigning() const { return fSigningEnabled; }
			bool				IsEncrypting() const
									{ return fEncryptionEnabled; }
			uint16				SessionFlags() const { return fSessionFlags; }
			uint32				ShareFlags() const { return fShareFlags; }
			uint32				MaximalAccess() const { return fMaximalAccess; }
			uint8				ShareType() const { return fShareType; }
			const char*			Host() const { return fHost; }
			const char*			Share() const { return fShare; }
			const char*			ServerName() const { return fServerName; }

	// Basic operations (paths are UTF-8, relative to the share root, using
	// either '/' or '\\' as separator).
			status_t			Create(const char* path, uint32 desiredAccess,
									uint32 shareAccess, uint32 disposition,
									uint32 createOptions, uint32 attributes,
									FileId& id, FileInfo* info = NULL,
									uint32* _createAction = NULL);
			status_t			Close(const FileId& id, FileInfo* info = NULL);
			status_t			Read(const FileId& id, uint64 offset,
									void* buffer, size_t length,
									size_t* _bytesRead);
			status_t			Write(const FileId& id, uint64 offset,
									const void* buffer, size_t length,
									size_t* _bytesWritten);
			status_t			Flush(const FileId& id);
			status_t			QueryInfo(const FileId& id, uint8 infoType,
									uint8 infoClass, uint32 additional,
									void* buffer, size_t bufferSize,
									size_t* _resultSize);
			status_t			SetInfo(const FileId& id, uint8 infoType,
									uint8 infoClass, const void* data,
									size_t length);
			status_t			QueryDirectory(const FileId& id,
									const char* pattern, uint8 flags,
									void* buffer, size_t bufferSize,
									size_t* _resultSize);
			status_t			Echo();

	// Convenience operations on open handles
			status_t			QueryFileInfo(const FileId& id,
									FileInfo& info);
			status_t			SetEndOfFile(const FileId& id, uint64 size);
			status_t			SetBasicInfo(const FileId& id,
									uint64 creationTime, uint64 lastAccessTime,
									uint64 lastWriteTime, uint64 changeTime,
									uint32 attributes);
			status_t			SetDisposition(const FileId& id,
									bool deleteOnClose);
			status_t			Rename(const FileId& id, const char* newPath,
									bool replace);

	// Compound, path based operations (single round trip each)
			status_t			QueryPathInfo(const char* path,
									FileInfo& info);
			status_t			QueryFsInfo(FsInfo& info);
			status_t			DeletePath(const char* path, bool directory);
			status_t			RenamePath(const char* from, const char* to,
									bool replace);
			status_t			CreateDirectoryPath(const char* path,
									FileInfo* info);
			status_t			SetPathBasicInfo(const char* path,
									uint64 creationTime, uint64 lastAccessTime,
									uint64 lastWriteTime, uint64 changeTime,
									uint32 attributes);
			status_t			SetPathEndOfFile(const char* path,
									uint64 size);

	// Parses a FileAllInformation buffer.
	static	status_t			ParseAllInformation(const uint8* data,
									size_t length, FileInfo& info);

private:
	struct Request;
	struct Frame;

			status_t			_EnsureConnected();
			status_t			_ConnectTransport();
			void				_CloseTransport();
			status_t			_Negotiate();
			status_t			_SessionSetup();
			status_t			_TreeConnect();
			void				_DeriveKeys();
			void				_PreauthUpdate(const uint8* data,
									size_t length);

			status_t			_SendReceive(Request* requests, int count);
			status_t			_SendAll(const uint8* data, size_t length);
			status_t			_ReceiveExactly(uint8* buffer, size_t length);
			status_t			_ReceiveFrame(Frame& frame);
			void				_FreeFrames();
			status_t			_ProcessFrame(Frame& frame,
									Request* requests, int count,
									int* _remaining);
			status_t			_DecryptFrame(Frame& frame);
			status_t			_EncryptSendBuffer();
			void				_SignMessage(uint8* message, size_t length);
			bool				_VerifyMessage(const uint8* message,
									size_t length);
			uint16				_CreditCharge(size_t payload) const;
			void				_FillHeader(uint8* header,
									const Request& request, uint32 flags,
									uint32 nextCommand);

			status_t			_ConvertPath(const char* path, Packet& out);
			void				_BuildCreate(Request& request,
									const Packet& pathUtf16,
									uint32 desiredAccess, uint32 shareAccess,
									uint32 disposition, uint32 createOptions,
									uint32 attributes);
			void				_BuildClose(Request& request,
									const FileId& id);
			void				_BuildQueryInfo(Request& request,
									const FileId& id, uint8 infoType,
									uint8 infoClass, uint32 additional,
									uint32 outputLength);
			void				_BuildSetInfo(Request& request,
									const FileId& id, uint8 infoType,
									uint8 infoClass, const void* data,
									size_t length);
			status_t			_ParseCreateResponse(const Request& request,
									FileId& id, FileInfo* info,
									uint32* _createAction);
			status_t			_ParseQueryInfoResponse(
									const Request& request,
									const uint8** _data, size_t* _length);
			status_t			_ParseFileInfoFromCreate(const uint8* data,
									FileInfo& info);
			status_t			_OpenSetClose(const char* path,
									uint32 desiredAccess, uint32 createOptions,
									uint8 infoClass, const void* data,
									size_t length);

private:
			Mutex				fLock;
			char				fHost[256];
			char				fShare[256];
			char				fServerName[64];
			uint16				fPort;
			char*				fUser;
			char*				fPassword;
			char*				fDomain;
			char*				fWorkstation;
			Options				fOptions;

			int					fSocket;
			bool				fConnected;
			uint32				fGeneration;

			uint16				fDialect;
			uint16				fServerSecurityMode;
			uint32				fServerCapabilities;
			uint32				fMaxTransactSize;
			uint32				fMaxReadSize;
			uint32				fMaxWriteSize;
			bool				fSupportsMultiCredit;
			uint8				fClientGuid[16];
			uint16				fCipher;

			uint64				fSessionId;
			uint32				fTreeId;
			uint16				fSessionFlags;
			uint8				fShareType;
			uint32				fShareFlags;
			uint32				fMaximalAccess;

			uint64				fNextMessageId;
			int32				fCredits;

			bool				fSigningEnabled;
			bool				fHaveSessionKey;
			uint8				fSessionKey[16];
			uint8				fSigningKey[16];
			uint8				fEncryptionKey[16];
			uint8				fDecryptionKey[16];
			crypto::AESCMAC		fSigningCmac;
			bool				fEncryptionEnabled;
			uint64				fNonceCounter;
			uint8				fNonceRandom[8];

			bool				fPreauthActive;
			uint8				fPreauthHash[64];

			Packet				fSendBuffer;
			uint8*				fReceiveBuffer;
			size_t				fReceiveBufferSize;
			bool				fReceiveBufferInUse;
			Frame*				fFrames;
			int					fFrameCount;
			int					fFrameCapacity;
};


}	// namespace smb2


#endif	// SMB2_CONNECTION_H
