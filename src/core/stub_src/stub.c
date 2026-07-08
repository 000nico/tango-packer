#include "core/memory/memory.h"
#include "core/pe/pe.h"
#include "core/patch/placeholders/placeholders.h"
#include "core/cryptography/xor/xor.h"

void entry_point() {
    volatile unsigned long long image_base = get_real_image_base();

    unsigned long long e_lfanew = *(unsigned int*)(image_base + 0x3C);
    unsigned long long pe_header_address = image_base + e_lfanew;
    unsigned long long pe_header_offset = *(unsigned int*)(image_base + e_lfanew);

    unsigned long long machine = *(unsigned int*)(pe_header_address + 4);
    unsigned long long number_of_sections = *(unsigned short*)(pe_header_address + 6);

    unsigned long long SizeOfOptionalHeader = *(unsigned short*)(pe_header_address + 4 + 16);
    unsigned long long section_headers_address = pe_header_address + 24 + SizeOfOptionalHeader;

    unsigned int text_rva, text_size;
    get_text_rva_and_size(&text_rva, &text_size, number_of_sections, section_headers_address);
    unsigned char* text_ptr = (unsigned char*)(image_base + text_rva);

    unencrypt(text_ptr, text_size, key);

    jump_to_original_entry_point(image_base + original_entry_point);
}