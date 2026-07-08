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
    unsigned long long flink;              // offset 0x00 - next node
    unsigned long long blink;              // offset 0x08 - previous node
    unsigned long long dll_base;           // offset 0x10 - base address of dll
    unsigned long long entry_point;        // offset 0x18
    unsigned long long size_of_image;      // offset 0x20
    unsigned short full_dll_name_length;   // offset 0x28
    unsigned short full_dll_name_max_length; // offset 0x2A
    unsigned int padding1;
    unsigned long long full_dll_name_buffer; // offset 0x30 - pointer to string name
} LDR_DATA_TABLE_ENTRY_INMEMORYORDER;
#pragma pack(pop)
