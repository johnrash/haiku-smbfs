/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 *
 * NTLMSSP (MS-NLMP) client authentication using NTLMv2.
 */
#ifndef SMB2_NTLM_H
#define SMB2_NTLM_H

#include "Buffer.h"
#include "Types.h"


namespace smb2 {


class NtlmContext {
public:
								NtlmContext();
								~NtlmContext();

			status_t			SetCredentials(const char* user,
									const char* password, const char* domain,
									const char* workstation);

			bool				IsAnonymous() const;

			status_t			CreateNegotiate(Packet& out);
			status_t			ProcessChallenge(const uint8* data,
									size_t length);
			status_t			CreateAuthenticate(Packet& out,
									const char* targetHost);

			bool				HasSessionKey() const
									{ return fHasSessionKey; }
			const uint8*		SessionKey() const { return fSessionKey; }

			const char*			TargetName() const { return fTargetName; }

private:
			status_t			_SetString(char** field, const char* value);
			void				_ComputeNtowfV2(uint8 out[16]);

private:
			char*				fUser;
			char*				fPassword;
			char*				fDomain;
			char*				fWorkstation;

			uint8				fServerChallenge[8];
			uint32				fServerFlags;
			uint8*				fTargetInfo;
			size_t				fTargetInfoLength;
			char				fTargetName[256];

			uint8*				fNegotiateMessage;
			size_t				fNegotiateLength;
			uint8*				fChallengeMessage;
			size_t				fChallengeLength;

			uint8				fSessionKey[16];
			bool				fHasSessionKey;
};


}	// namespace smb2


#endif	// SMB2_NTLM_H
