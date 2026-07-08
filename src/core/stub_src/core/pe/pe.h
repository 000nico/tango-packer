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

void get_text_rva_and_size(unsigned int* text_rva, unsigned int* text_size, unsigned long long number_of_sections, unsigned long long section_headers_address);