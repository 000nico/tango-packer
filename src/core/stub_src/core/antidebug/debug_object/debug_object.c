#include "../../peb/peb.h"
#include "../../winapi/imports.h"
#include "../../winapi/constants.h"

int debug_object_check(void) {
    void*         debugObjectHandle = 0;
    unsigned long returnLength      = 0;
    NTSTATUS      status;

    NtQueryInformationProcess_t QueryProcessInfo =
        (NtQueryInformationProcess_t)pebget(L"ntdll.dll", "NtQueryInformationProcess");

    if (!QueryProcessInfo) return 0;

    status = QueryProcessInfo(
        (void*)(unsigned long long)-1,
        ProcessDebugObjectHandle,
        &debugObjectHandle,
        sizeof(debugObjectHandle),
        &returnLength
    );

    if (status == 0 && debugObjectHandle != 0) return 1;
    return 0;
}
