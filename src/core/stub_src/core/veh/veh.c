/* Vectored Exception Handling: decrypt .text pages on demand.
   Pages are marked as non-executable (PAGE_READWRITE). When execution hits a page,
   the OS throws EXCEPTION_ACCESS_VIOLATION (DEP). The VEH handler decrypts the page
   and marks it executable so execution can continue.

   TODO: Re-encrypt previously decrypted pages when execution leaves them.
   This requires tracking the "active page" and restoring PAGE_READWRITE + re-encrypting
   when the next DEP fault occurs on a different page. Needs correct CONTEXT.Rip offset. */

#include "veh.h"
#include "../winapi/constants.h"
#include "../winapi/imports.h"
#include "../peb/peb.h"
#include "../crypto/xor.h"

static long handler(struct _EXCEPTION_POINTERS* ExceptionInfo);

static VirtualProtect_t VirtualProtect;
static VirtualQuery_t VirtualQuery;
static unsigned long long veh_key;
static unsigned char* veh_text_ptr;
static unsigned int veh_text_size;

void start_veh(unsigned long long k, unsigned char* tptr, unsigned int tsize){
    veh_key = k;
    veh_text_ptr = tptr;
    veh_text_size = tsize;
    // resolve fns
    void* vq_addr = pebget(L"kernel32.dll", "VirtualQuery");
    VirtualQuery = (VirtualQuery_t)vq_addr;

    void* vp_addr = pebget(L"kernel32.dll", "VirtualProtect");
    VirtualProtect = (VirtualProtect_t)vp_addr;

    void* aveh_addr = pebget(L"ntdll.dll", "RtlAddVectoredExceptionHandler");

    AddVectoredExceptionHandler_t AddVectoredExceptionHandler = (AddVectoredExceptionHandler_t)aveh_addr;
    AddVectoredExceptionHandler(1, &handler);
}

static long handler(struct _EXCEPTION_POINTERS* ExceptionInfo){
    if(ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID exception_addr = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

    if(ExceptionInfo->ExceptionRecord->ExceptionInformation[0] != 8) // 8 = DEP/Execute
        return EXCEPTION_CONTINUE_SEARCH;

    if(exception_addr < (PVOID)veh_text_ptr || exception_addr >= (PVOID)(veh_text_ptr + veh_text_size))
        return EXCEPTION_CONTINUE_SEARCH;

    // Calculate page boundaries (4KB pages on x86/x64)
    unsigned long long page_base = ((unsigned long long)exception_addr) & ~0xFFFULL;
    
    // Change permissions only for this specific page
    DWORD oldProtect = 0;
    VirtualProtect((PVOID)page_base, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Calculate exact overlapping region to avoid decrypting unencrypted padding
    unsigned long long text_start = (unsigned long long)veh_text_ptr;
    unsigned long long text_end = text_start + veh_text_size;
    
    unsigned long long decrypt_start = page_base > text_start ? page_base : text_start;
    unsigned long long page_end = page_base + 0x1000;
    unsigned long long decrypt_end = page_end < text_end ? page_end : text_end;

    // decrypt only the valid chunk within this page
    unencrypt((unsigned char*)decrypt_start, (unsigned int)(decrypt_end - decrypt_start), veh_key);

    return EXCEPTION_CONTINUE_EXECUTION;
}