/* Anti-debug orchestrator.
   Includes all check implementations directly so the linker emits
   intra-module calls (RIP-relative) instead of cross-object PLT stubs
   that break in position-independent shellcode. */

#include "antidebug.h"
#include "peb_flag/peb_flag.h"
#include "debug_object/debug_object.h"
#include "hide_thread/hide_thread.h"
#include "rdtscp/rdtscp.h"
#include "injection_protect/injection_protect.h"
#include "../peb/peb.h"
#include "../sdk/io/io.h"
#include "../winapi/imports.h"

/* Pull check implementations into this translation unit so every call
   is a direct RIP-relative branch — required for PIC shellcode. */
#include "peb_flag/peb_flag.c"
#include "debug_object/debug_object.c"
#include "hide_thread/hide_thread.c"
#include "rdtscp/rdtscp.c"
#include "injection_protect/injection_protect.c"

#define ANTIDEBUG_POLL_MS 1000

static Sleep_t cached_Sleep;

static int run_checks(void) {
    if (peb_check())          return 1;
    if (debug_object_check()) return 1;
    if (rdtscp_check())       return 1;
    return 0;
}

static void response(void) {
    ExitProcess_t myExitProcess = (ExitProcess_t)pebget(L"kernel32.dll", "ExitProcess");
    if (myExitProcess)
        myExitProcess(0xDEAD);
    while(1) { __asm__ __volatile__ ("hlt"); }
}

static unsigned long __stdcall antidebug_thread(void* param) {
    (void)param;

    hide_from_debugger();
    int injproc = setProcessMitigationCodePolicy();
    my_puts(injproc == 1 ? "spmcp ok" : injproc == 0 ? "spmcp failed" : "null");

    while (1) {
        if (cached_Sleep)
            cached_Sleep(ANTIDEBUG_POLL_MS);

        if (run_checks())
            response();
    }

    return 0;
}

int antidebug_start(void) {
    hide_from_debugger();
    my_puts("anti-debug: main thread hidden from debugger");

    if (run_checks()) {
        my_puts("anti-debug: debugger detected on initial check");
        return 1;
    }

    my_puts("anti-debug: initial checks passed");

    cached_Sleep = (Sleep_t)pebget(L"kernel32.dll", "Sleep");

    CreateThread_t myCreateThread = (CreateThread_t)pebget(L"kernel32.dll", "CreateThread");

    if (myCreateThread) {
        myCreateThread(0, 0, (void*)antidebug_thread, 0, 0, 0);
        my_puts("anti-debug: polling thread started");
    }

    return 0;
}
