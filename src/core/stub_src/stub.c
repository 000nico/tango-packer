#include "core/memory/memory.h"
#include "core/pe/pe.h"
#include "core/crypto/xor.h"
#include "core/peb/peb.h"
#include "core/sdk/strings/strings.h"
#include "core/veh/veh.h"
#include "core/antidebug/antidebug.h"
#include "core/winapi/imports.h"
#include "core/winapi/constants.h"
#include "core/sdk/io/io.h"
#include "stub.h"

// Placeholder values patched by the Rust packer before embedding into the PE.
// These MUST be defined in the same translation unit as stub_main() so the
// compiler emits direct RIP-relative accesses. If they are extern (from a
// separate .c file), MinGW generates .refptr GOT-like entries with absolute
// addresses that break in position-independent shellcode.
volatile unsigned long long original_entry_point = 0xDEADBEEF;

// 32-byte key for ChaCha20
__attribute__((aligned(16))) volatile unsigned char chacha_key[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

// 12-byte nonce for ChaCha20
__attribute__((aligned(16))) volatile unsigned char chacha_nonce[12] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 
    0x12, 0x34, 0x56, 0x78
};

// Local working variables for .text section info
unsigned int text_rva, text_size;
unsigned char* text_ptr;

void stub_main() {
    // Apply anti-debug protections to main thread and spawn polling thread
    if (antidebug_start()) {
        //my_puts("debugger detected, halting");
        while(1) { __asm__ __volatile__ ("pause"); }
    }

    volatile unsigned long long image_base = get_real_image_base();

    unsigned long long e_lfanew = *(unsigned int*)(image_base + 0x3C);
    unsigned long long pe_header_address = image_base + e_lfanew;

    unsigned short number_of_sections = *(unsigned short*)(pe_header_address + 6);
    unsigned short SizeOfOptionalHeader = *(unsigned short*)(pe_header_address + 20);

    unsigned long long section_headers_address = pe_header_address + 24 + SizeOfOptionalHeader;

    get_text_rva_and_size(&text_rva, &text_size, number_of_sections, section_headers_address);

    text_ptr = (unsigned char*)(image_base + text_rva);

    // VEH path: register handler, make .text non-executable so DEP faults
    // trigger on-demand decryption via the vectored exception handler.
    start_veh((unsigned char*)chacha_key, (unsigned char*)chacha_nonce, text_ptr, text_size);
    //my_puts("VEH started");

    unsigned int oldProtect;
    VirtualProtect_t myVirtualProtect = (VirtualProtect_t)pebget(L"kernel32.dll", "VirtualProtect");
    myVirtualProtect(text_ptr, text_size, PAGE_READWRITE, &oldProtect);
    
    /* 
    // Direct decryption path (VEH disabled):
    // Resolve VirtualProtect independently, decrypt the entire .text section
    // upfront, then restore execute permissions before jumping to OEP.
    VirtualProtect_t myVirtualProtect = (VirtualProtect_t)pebget(L"kernel32.dll", "VirtualProtect");

    unsigned int oldProtect;
    myVirtualProtect(text_ptr, text_size, PAGE_READWRITE, &oldProtect);

    unencrypt(text_ptr, text_size, key);

    myVirtualProtect(text_ptr, text_size, PAGE_EXECUTE_READ, &oldProtect);
    */

    jump_to_original_entry_point(image_base + original_entry_point);
    //my_puts("jmp'ed to OEP");
}