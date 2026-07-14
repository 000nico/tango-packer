#include "core/memory/memory.h"
#include "core/pe/pe.h"
#include "core/patch/placeholders.c"
#include "core/crypto/xor.h"
#include "core/peb/peb.h"
#include "core/sdk/strings/strings.h"
#include "core/winapi/imports.h"
#include "core/winapi/constants.h"

void stub_main() {
    volatile unsigned long long image_base = get_real_image_base();

    unsigned long long e_lfanew = *(unsigned int*)(image_base + 0x3C);
    unsigned long long pe_header_address = image_base + e_lfanew;

    unsigned short number_of_sections = *(unsigned short*)(pe_header_address + 6);
    unsigned short SizeOfOptionalHeader = *(unsigned short*)(pe_header_address + 20);

    unsigned long long section_headers_address = pe_header_address + 24 + SizeOfOptionalHeader;

    unsigned int text_rva, text_size;
    get_text_rva_and_size(&text_rva, &text_size, number_of_sections, section_headers_address);
    
    unsigned char* text_ptr = (unsigned char*)(image_base + text_rva);

    void* vp_addr = pebget(L"kernel32.dll", "VirtualProtect");
    VirtualProtect_t VirtualProtect = (VirtualProtect_t)vp_addr;

    unsigned int oldProtect;

    unencrypt(text_ptr, text_size, key);

    jump_to_original_entry_point(image_base + original_entry_point);
}