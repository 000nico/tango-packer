/* the goal is use Vectored Exception Handling so we can decrypt only the necessary pages,
the ones being used. Marking every page as non executable, the OS will throw an exception (EXCEPTION_ACCESS_VIOLATION 0xC0000005) 
A thread will handle this exception. search for the page trying to be executed, decrypting it, adding permission for execution
then check rip, and encrypt again the page if its not being executed anymore */

#include "../memory/functions_structs.h"
#include "veh.h"
#include "../memory/peb_walking.h"
#include "../cryptography/xor/xor.h"
#include "../patch/placeholders/placeholders.h"

long handler(struct _EXCEPTION_POINTERS* ExceptionInfo);

void start_veh(){
    void* aveh_addr = pebget(L"kernel32.dll", "AddVectoredExceptionHandler");
    AddVectoredExceptionHandler_t AddVectoredExceptionHandler = (AddVectoredExceptionHandler_t)aveh_addr;

    AddVectoredExceptionHandler(1, &handler);
}

long handler(struct _EXCEPTION_POINTERS* ExceptionInfo){
    if(ExceptionInfo->ExceptionRecord->ExceptionCode != 0xC0000005)
        return 0; // 0 equals to EXCEPTION_CONTINUE_SEARCH

    PVOID exception_addr = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

    void* vq_addr = pebget(L"kernel32.dll", "VirtualQuery");
    VirtualQuery_t VirtualQuery = (VirtualQuery_t)vq_addr;

    struct _MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(exception_addr, &mbi, sizeof(mbi));

    void* vp_addr = pebget(L"kernel32.dll", "VirtualProtect");
    VirtualProtect_t VirtualProtect = (VirtualProtect_t)vp_addr;

    // change permissions
    DWORD oldProtect = 0;
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // decrypt
    unencrypt(mbi.BaseAddress, mbi.RegionSize, key);

    return -1; // equals to EXCEPTION_CONTINUE_EXECUTION
}