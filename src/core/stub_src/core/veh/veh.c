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
#include "../patch/placeholders.h"
#include "../../stub.h"

long handler(struct _EXCEPTION_POINTERS* ExceptionInfo);

VirtualProtect_t VirtualProtect;
VirtualQuery_t VirtualQuery;

void start_veh(){
    // resolve fns
    void* vq_addr = pebget(L"kernel32.dll", "VirtualQuery");
    VirtualQuery = (VirtualQuery_t)vq_addr;

    void* vp_addr = pebget(L"kernel32.dll", "VirtualProtect");
    VirtualProtect = (VirtualProtect_t)vp_addr;

    void* aveh_addr = pebget(L"ntdll.dll", "RtlAddVectoredExceptionHandler");

    AddVectoredExceptionHandler_t AddVectoredExceptionHandler = (AddVectoredExceptionHandler_t)aveh_addr;
    AddVectoredExceptionHandler(1, &handler);
}

long handler(struct _EXCEPTION_POINTERS* ExceptionInfo){
    if(ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID exception_addr = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

    if(ExceptionInfo->ExceptionRecord->ExceptionInformation[0] != 8) // 8 = DEP/Execute
        return EXCEPTION_CONTINUE_SEARCH;

    if(exception_addr < (PVOID)text_ptr || exception_addr >= (PVOID)(text_ptr + text_size))
        return EXCEPTION_CONTINUE_SEARCH;

    struct _MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(exception_addr, &mbi, sizeof(mbi));

    // change permissions
    DWORD oldProtect = 0;
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // decrypt
    unencrypt(mbi.BaseAddress, mbi.RegionSize, key);

    return EXCEPTION_CONTINUE_EXECUTION;
}