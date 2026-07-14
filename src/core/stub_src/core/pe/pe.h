#ifndef PE_H
#define PE_H

#include "../winapi/constants.h"

// ---------- SECTION HEADER ----------
#pragma pack(push, 1)
typedef struct {
    unsigned char name[8];
    unsigned int virtual_size;
    unsigned int virtual_address;
    unsigned int size_of_raw_data;
    unsigned int pointer_to_raw_data;
    unsigned int pointer_to_relocations;
    unsigned int pointer_to_line_numbers;
    unsigned short number_of_relocations;
    unsigned short number_of_line_numbers;
    unsigned int characteristics;
} SectionHeader;
#pragma pack(pop)

#pragma pack(push, 1)

// ---------- DOS HEADER ----------
typedef struct _IMAGE_DOS_HEADER {
    unsigned short e_magic;      // "MZ" = 0x5A4D
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
    unsigned short e_res[4];
    unsigned short e_oemid;
    unsigned short e_oeminfo;
    unsigned short e_res2[10];
    long           e_lfanew;     // offset to NT_HEADERS
} IMAGE_DOS_HEADER;

// ---------- FILE HEADER ----------
typedef struct _IMAGE_FILE_HEADER {
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned int   TimeDateStamp;
    unsigned int   PointerToSymbolTable;
    unsigned int   NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;
} IMAGE_FILE_HEADER;

// ---------- DATA DIRECTORY ----------
typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned int VirtualAddress;
    unsigned int Size;
} IMAGE_DATA_DIRECTORY;

// ---------- OPTIONAL HEADER 64 ----------
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    unsigned short Magic;                 // 0x20b = PE32+
    unsigned char  MajorLinkerVersion;
    unsigned char  MinorLinkerVersion;
    unsigned int   SizeOfCode;
    unsigned int   SizeOfInitializedData;
    unsigned int   SizeOfUninitializedData;
    unsigned int   AddressOfEntryPoint;
    unsigned int   BaseOfCode;
    unsigned long long ImageBase;
    unsigned int   SectionAlignment;
    unsigned int   FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned int   Win32VersionValue;
    unsigned int   SizeOfImage;
    unsigned int   SizeOfHeaders;
    unsigned int   CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long long SizeOfStackReserve;
    unsigned long long SizeOfStackCommit;
    unsigned long long SizeOfHeapReserve;
    unsigned long long SizeOfHeapCommit;
    unsigned int   LoaderFlags;
    unsigned int   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

// ---------- NT HEADERS 64 ----------
typedef struct _IMAGE_NT_HEADERS64 {
    unsigned int Signature;      // "PE\0\0" = 0x00004550
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

// ---------- EXPORT DIRECTORY ----------
typedef struct _IMAGE_EXPORT_DIRECTORY {
    unsigned int Characteristics;
    unsigned int TimeDateStamp;
    unsigned short MajorVersion;
    unsigned short MinorVersion;
    unsigned int Name;
    unsigned int Base;
    unsigned int NumberOfFunctions;
    unsigned int NumberOfNames;
    unsigned int AddressOfFunctions;     
    unsigned int AddressOfNames;         
    unsigned int AddressOfNameOrdinals;  
} IMAGE_EXPORT_DIRECTORY;

#pragma pack(pop)

void get_text_rva_and_size(unsigned int* text_rva, unsigned int* text_size, unsigned long long number_of_sections, unsigned long long section_headers_address);

#endif // PE_H