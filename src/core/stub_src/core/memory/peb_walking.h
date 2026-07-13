#pragma pack(push, 1)
typedef struct {
    unsigned char reserved1[0x10];        // offset 0x00 
    unsigned long long image_base_address; // offset 0x10
    unsigned long long ldr;                // offset 0x18 -> pointer to PEB_LDR_DATA
} PEB;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    unsigned char reserved1[0x20];              
    unsigned long long in_memory_order_module_list_flink; // offset 0x20 -> first node of list
} PEB_LDR_DATA;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    unsigned long long flink;              // 0x00
    unsigned long long blink;              // 0x08
    unsigned char reserved[16];            // 0x10 - InInitializationOrderLinks
    unsigned long long dll_base;           // 0x20
    unsigned long long entry_point;        // 0x28
    unsigned int size_of_image;            // 0x30
    unsigned int padding1;                 // 0x34
    unsigned short full_dll_name_length;   // 0x38
    unsigned short full_dll_name_max_length; // 0x3A
    unsigned int padding2;                 // 0x3C
    unsigned long long full_dll_name_buffer; // 0x40
    unsigned short base_dll_name_length;   // 0x48
    unsigned short base_dll_name_max_length; // 0x4A
    unsigned int padding3;                 // 0x4C
    unsigned long long base_dll_name_buffer; // 0x50
} LDR_DATA_TABLE_ENTRY_INMEMORYORDER;
#pragma pack(pop)

void* pebget(unsigned short* dllname, char* fn_name);