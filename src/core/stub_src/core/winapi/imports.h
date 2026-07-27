#ifndef WINAPI_IMPORTS_H
#define WINAPI_IMPORTS_H

#include "../ntdef.h"
#include "structs.h"

// Function pointer typedefs for APIs resolved via PEB walking.
// Add new imported function typedefs here.

typedef int (*SetProcessMitigationPolicy_t)(
    int                 MitigationPolicy,
    void*               lpBuffer,
    unsigned long long  dwLength
);

typedef void* (__stdcall *GetProcAddress_t)(
    void*  hModule,
    const char* lpProcName
);

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

typedef NTSTATUS (__stdcall *NtQueryInformationProcess_t)(
    void*          ProcessHandle,
    unsigned int   ProcessInformationClass,
    void*          ProcessInformation,
    unsigned long  ProcessInformationLength,
    unsigned long* ReturnLength
);

typedef NTSTATUS (__stdcall *NtSetInformationThread_t)(
    void*          ThreadHandle,
    unsigned int   ThreadInformationClass,
    void*          ThreadInformation,
    unsigned long  ThreadInformationLength
);

typedef void* (__stdcall *CreateThread_t)(
    void*          lpThreadAttributes,
    SIZE_T         dwStackSize,
    void*          lpStartAddress,
    void*          lpParameter,
    unsigned long  dwCreationFlags,
    unsigned long* lpThreadId
);

typedef void (__stdcall *Sleep_t)(
    unsigned long dwMilliseconds
);

typedef void (__stdcall *ExitProcess_t)(
    unsigned int uExitCode
);

#endif // WINAPI_IMPORTS_H
