#include "peb_walking.h"

unsigned long long get_peb_address(void) {
    unsigned long long peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r" (peb));
    return peb;
}

unsigned long long get_image_base_address(void) {
    unsigned long long peb = get_peb_address();
    return *(unsigned long long*)(peb + 0x10);
}

// warning
// for example, if you search kernel32.dll, it can match with, for example, kernel32legacy.dll
unsigned long long pebgetdll(unsigned char* name, int valids){
    PEB* peb = (PEB*)get_peb_address();

    PEB_LDR_DATA* peb_ldr_data = (PEB_LDR_DATA*)peb->ldr;
    
    LDR_DATA_TABLE_ENTRY_INMEMORYORDER* first_node = (LDR_DATA_TABLE_ENTRY_INMEMORYORDER*)peb_ldr_data->in_memory_order_module_list_flink;
    LDR_DATA_TABLE_ENTRY_INMEMORYORDER* start_node = first_node;

    while(1){
        unsigned short* dll_name = (unsigned short *)first_node->full_dll_name_buffer;

        int matches = 1;
        for (int i = 0; i < valids; i++) {
            if ((unsigned char)name[i] != (unsigned char)(dll_name[i] & 0xFF)) {
                matches = 0;
                break;
            }
        }

        if (matches) 
            return first_node->dll_base; // found
        

        first_node = (LDR_DATA_TABLE_ENTRY_INMEMORYORDER*)first_node->flink;

        // iterated through the entire list and didnt found
        if (first_node == start_node) 
            return 0;
    }
}