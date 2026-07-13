int VirtualProtect(
    void* lpAddress,
    unsigned long long dwSize,
    unsigned int flNewProtect,
    unsigned int* lpflOldProtect
);

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

typedef int (*VirtualProtect_t)(void*, unsigned long long, unsigned int, unsigned int*);
