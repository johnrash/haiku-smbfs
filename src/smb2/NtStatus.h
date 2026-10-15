/*
 * Copyright 2026, Haiku SMB project.
 * Distributed under the terms of the MIT License.
 */
#ifndef SMB2_NT_STATUS_H
#define SMB2_NT_STATUS_H

#include "Types.h"


namespace smb2 {


// Maps an NT status code to a Haiku status_t error code.
status_t NtStatusToError(uint32 ntStatus);

// Returns a symbolic name for well known NT status codes.
const char* NtStatusName(uint32 ntStatus);


}	// namespace smb2


#endif	// SMB2_NT_STATUS_H
