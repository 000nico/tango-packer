#ifndef WINAPI_CONSTANTS_H
#define WINAPI_CONSTANTS_H

// Memory protection constants
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

// Exception handling constants
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define EXCEPTION_CONTINUE_EXECUTION -1
#define EXCEPTION_CONTINUE_SEARCH     0
#define EXCEPTION_ACCESS_VIOLATION    0xC0000005

// PE directory entry indices
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0

#endif // WINAPI_CONSTANTS_H
