#include "peb.h"
#include "../pe/pe.h"
#include "../sdk/strings/strings.h"

unsigned long long get_peb_address(void) {
    unsigned long long peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r" (peb));
    return peb;
}

unsigned long long get_image_base_address(void) {
    unsigned long long peb = get_peb_address();
    return *(unsigned long long*)(peb + 0x10);
}

unsigned long long pebgetdll(unsigned short* name){
    PEB* peb = (PEB*)get_peb_address();

    PEB_LDR_DATA* peb_ldr_data = (PEB_LDR_DATA*)peb->ldr;
    
    LDR_DATA_TABLE_ENTRY_INMEMORYORDER* first_node = (LDR_DATA_TABLE_ENTRY_INMEMORYORDER*)peb_ldr_data->in_memory_order_module_list_flink;
    LDR_DATA_TABLE_ENTRY_INMEMORYORDER* start_node = first_node;

    while(1){
        unsigned short* dll_name = (unsigned short *)first_node->base_dll_name_buffer;

        if(dll_name && !my_wcsicmp(name, dll_name)){
            return first_node->dll_base;
            break;
        }
        
        first_node = (LDR_DATA_TABLE_ENTRY_INMEMORYORDER*)first_node->flink;

        // iterated through the entire list and didnt found
        if (first_node == start_node) 
            return 0;
    }
}

// eat walking
void* eatget(unsigned long long dll_base, char* fn_name){
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(dll_base + dos->e_lfanew);

    unsigned int exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(dll_base + exportRVA);

    // array of names
    unsigned int* namesArray = (unsigned int*)(dll_base + exportDir->AddressOfNames);
    void* func = 0;
    for(unsigned int i = 0; i < exportDir->NumberOfNames; i++){
        char* funcName = (char*)(dll_base + namesArray[i]);

        if(!my_strcmp(funcName, fn_name)){
            unsigned short* ordinals = (unsigned short*)(dll_base + exportDir->AddressOfNameOrdinals);
            unsigned int* functions = (unsigned int*)(dll_base + exportDir->AddressOfFunctions);

            unsigned short ordinal = ordinals[i];
            func = (void*)(dll_base + functions[ordinal]);

            break;
        }
    }

    return func;
}

// abstraction for everything here
void* pebget(unsigned short* dllname, char* fn_name){
    unsigned long long dll_base = pebgetdll(dllname);
    return eatget(dll_base, fn_name);
}

// example
// void* addr = pebget(L"ntdll.dll", "NtProtectVirtualMemory");
// NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)addr;
