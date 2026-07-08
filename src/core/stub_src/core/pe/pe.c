#include "pe.h"

void get_text_rva_and_size(unsigned int* text_rva, unsigned int* text_size, unsigned long long number_of_sections, unsigned long long section_headers_address){
    SectionHeader* sections = (SectionHeader*)section_headers_address;
    for(int i = 0; i < number_of_sections; i++){
        SectionHeader *current = &sections[i];

        if( current->name[0] == '.' &&
            current->name[1] == 't' &&
            current->name[2] == 'e' &&
            current->name[3] == 'x' &&
            current->name[4] == 't'){

                *text_rva = current->virtual_address;
                *text_size = current->virtual_size;

                break;
            }
    }
}