#ifndef WINAPI_STRUCTS_H
#define WINAPI_STRUCTS_H

#include "../ntdef.h"
#include "constants.h"

// ---------- EXCEPTION_RECORD ----------
typedef struct _EXCEPTION_RECORD {
    DWORD     ExceptionCode;
    DWORD     ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID     ExceptionAddress;
    DWORD     NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

// ---------- CONTEXT (x64) ----------
typedef struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    
    unsigned short SegCs;
    unsigned short SegDs;
    unsigned short SegEs;
    unsigned short SegFs;
    unsigned short SegGs;
    unsigned short SegSs;
    DWORD EFlags;
    
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    
    DWORD64 Rip;
    
} CONTEXT, *PCONTEXT;

// ---------- EXCEPTION_POINTERS ----------
typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

// ---------- MEMORY_BASIC_INFORMATION ----------
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    WORD   PartitionId;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

#endif // WINAPI_STRUCTS_H
