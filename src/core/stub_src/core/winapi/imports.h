#ifndef WINAPI_IMPORTS_H
#define WINAPI_IMPORTS_H

#include "../ntdef.h"
#include "structs.h"

// Function pointer typedefs for APIs resolved via PEB walking.
// Add new imported function typedefs here.

typedef int (__stdcall *VirtualProtect_t)(
    void*         lpAddress,
    unsigned long long dwSize,
    unsigned int  flNewProtect,
    unsigned int* lpflOldProtect
);

typedef void* (__stdcall *GetStdHandle_t)(
    unsigned int nStdHandle
);

typedef int (__stdcall *WriteFile_t)(
    void*         hFile,
    const void*   lpBuffer,
    unsigned int  nNumberOfBytesToWrite,
    unsigned int* lpNumberOfBytesWritten,
    void*         lpOverlapped
);

typedef SIZE_T (__stdcall *VirtualQuery_t)(
    void*                              lpAddress,
    struct _MEMORY_BASIC_INFORMATION*  lpBuffer,
    SIZE_T                             dwLength
);

typedef void* (__stdcall *AddVectoredExceptionHandler_t)(
    unsigned long First,
    void*         Handler
);

typedef long (*PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS* ExceptionInfo);

#endif // WINAPI_IMPORTS_H
