#include "../../peb/peb.h"
#include "../../winapi/imports.h"
#include "../../winapi/constants.h"

void hide_from_debugger(void) {
    NtSetInformationThread_t SetInformationThread =
        (NtSetInformationThread_t)pebget(L"ntdll.dll", "NtSetInformationThread");

    if (!SetInformationThread) return;

    SetInformationThread(
        (void*)(unsigned long long)-2,
        ThreadHideFromDebugger,
        0,
        0
    );
}
