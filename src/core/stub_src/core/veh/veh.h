
typedef unsigned int       DWORD;
typedef unsigned long long DWORD64;
typedef unsigned long long ULONG_PTR;
typedef void*              PVOID;
typedef unsigned long      ULONG;
typedef unsigned long long ULONG_PTR;
typedef unsigned int* PDWORD;

#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define EXCEPTION_CONTINUE_EXECUTION -1
#define EXCEPTION_CONTINUE_SEARCH     0
#define EXCEPTION_ACCESS_VIOLATION    0xC0000005

typedef struct _EXCEPTION_RECORD {
    DWORD     ExceptionCode;
    DWORD     ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID     ExceptionAddress;
    DWORD     NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    
    unsigned short SegCs;
    unsigned short SegDs;
    unsigned short SegEs;
    unsigned short SegFs;
    unsigned short SegGs;
    unsigned short SegSs;
    DWORD EFlags;
    
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    
    // Instruction Pointer
    DWORD64 Rip;
    
} CONTEXT, *PCONTEXT;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

typedef long (*PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS* ExceptionInfo);

typedef void* (__stdcall *AddVectoredExceptionHandler_t)(
    unsigned long First,
    void* Handler
);

typedef unsigned long long SIZE_T;
typedef unsigned short     WORD;

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;         // Dirección base de la página/región
    PVOID  AllocationBase;      // Dirección base de la asignación original
    DWORD  AllocationProtect;   // Permisos originales al momento del VirtualAlloc
    WORD   PartitionId;         // ID de partición (agregado en versiones modernas de Windows)
    SIZE_T RegionSize;          // Tamaño de la región en bytes
    DWORD  State;               // Estado de la memoria (MEM_COMMIT, MEM_FREE, etc.)
    DWORD  Protect;             // Permisos de acceso actuales (PAGE_READWRITE, PAGE_EXECUTE, etc.)
    DWORD  Type;                // Tipo de memoria (MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE)
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef SIZE_T (__stdcall *VirtualQuery_t)(
    void* lpAddress,
    struct _MEMORY_BASIC_INFORMATION* lpBuffer,
    SIZE_T dwLength
);