use crate::core::cryptography::xor::xor_bytes;
use crate::core::parser::pe::*;
use crate::sdk::write_memory::write_bytes::*;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
fn executable_sections(sections: &[SectionHeader]) -> Vec<&SectionHeader> {
    sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .collect()
}

pub fn encrypt_executable_sections(aob: &mut [u8], pe: &PE, key: u8) -> Result<(), String>  {

    let sections: &Vec<SectionHeader> = match pe {
        PE::PE32(p) => &p.sections,
        PE::PE64(p) => &p.sections
    };

    for s in sections {
        let is_executable = s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

        if !is_executable {
            continue;
        }
        
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;

        if end > aob.len() {
            return Err(format!("section out of bounds").to_string());
        }

        xor_bytes(&mut aob[start..end], key);
        
    }

    Ok(())
}

fn write_dos_header(buf: &mut Vec<u8>, dos: &DOSMZHeader) {
    write_u16(buf, 0x00, dos.e_magic);
    write_u16(buf, 0x02, dos.e_cblp);
    write_u16(buf, 0x04, dos.e_cp);
    write_u16(buf, 0x06, dos.e_crlc);
    write_u16(buf, 0x08, dos.e_cparhdr);
    write_u16(buf, 0x0A, dos.e_minalloc);
    write_u16(buf, 0x0C, dos.e_maxalloc);
    write_u16(buf, 0x0E, dos.e_ss);
    write_u16(buf, 0x10, dos.e_sp);
    write_u16(buf, 0x12, dos.e_csum);
    write_u16(buf, 0x14, dos.e_ip);
    write_u16(buf, 0x16, dos.e_cs);
    write_u16(buf, 0x18, dos.e_lfarlc);
    write_u16(buf, 0x1A, dos.e_ovno);
    for (i, v) in dos.e_res.iter().enumerate() {
        write_u16(buf, 0x1C + i * 2, *v);
    }
    write_u16(buf, 0x24, dos.e_oemid);
    write_u16(buf, 0x26, dos.e_oeminfo);
    for (i, v) in dos.e_res2.iter().enumerate() {
        write_u16(buf, 0x28 + i * 2, *v);
    }
    write_u32(buf, 0x3C, dos.e_lfanew);
}

fn write_pe_header(buf: &mut Vec<u8>, offset: usize, pe: &PEHeader) {
    write_u32(buf, offset, pe.signature);
    write_u16(buf, offset + 4, pe.machine);
    write_u16(buf, offset + 6, pe.number_of_sections);
    write_u32(buf, offset + 8, pe.time_date_stamp);
    write_u32(buf, offset + 12, pe.pointer_to_symbol_table);
    write_u32(buf, offset + 16, pe.number_of_symbols);
    write_u16(buf, offset + 20, pe.size_of_optional_header);
    write_u16(buf, offset + 22, pe.characteristics);
}

fn write_optional_header32(buf: &mut Vec<u8>, o: usize, oh: &OptionalHeader32) {
    write_u16(buf, o + 0, oh.magic);
    buf_set(buf, o + 2, oh.major_linker_version);
    buf_set(buf, o + 3, oh.minor_linker_version);
    write_u32(buf, o + 4, oh.size_of_code);
    write_u32(buf, o + 8, oh.size_of_initialized_data);
    write_u32(buf, o + 12, oh.size_of_unitialized_data);
    write_u32(buf, o + 16, oh.address_of_entry_point);
    write_u32(buf, o + 20, oh.base_of_code);
    write_u32(buf, o + 24, oh.base_of_data);
    write_u32(buf, o + 28, oh.image_base);
    write_u32(buf, o + 32, oh.section_alignment);
    write_u32(buf, o + 36, oh.file_alignment);
    write_u16(buf, o + 40, oh.major_operating_system_version);
    write_u16(buf, o + 42, oh.minor_operating_system_version);
    write_u16(buf, o + 44, oh.major_image_version);
    write_u16(buf, o + 46, oh.minor_image_version);
    write_u16(buf, o + 48, oh.major_subsystem_version);
    write_u16(buf, o + 50, oh.minor_subsystem_version);
    write_u32(buf, o + 52, oh.reserved1);
    write_u32(buf, o + 56, oh.size_of_image);
    write_u32(buf, o + 60, oh.size_of_headers);
    write_u32(buf, o + 64, oh.check_sum);
    write_u16(buf, o + 68, oh.subsystem);
    write_u16(buf, o + 70, oh.dll_characteristics);
    write_u32(buf, o + 72, oh.size_of_stack_reserve);
    write_u32(buf, o + 76, oh.size_of_stack_commit);
    write_u32(buf, o + 80, oh.size_of_heap_reserve);
    write_u32(buf, o + 84, oh.size_of_heap_commit);
    write_u32(buf, o + 88, oh.loader_flags);
    write_u32(buf, o + 92, oh.number_of_rva_and_sizes);
    write_u32(buf, o + 96, oh.export_directory_va);
    write_u32(buf, o + 100, oh.export_directory_size);
    write_u32(buf, o + 104, oh.import_directory_va);
    write_u32(buf, o + 108, oh.import_directory_size);
    write_u32(buf, o + 112, oh.resource_directory_va);
    write_u32(buf, o + 116, oh.resource_directory_size);
    write_u32(buf, o + 120, oh.exception_directory_va);
    write_u32(buf, o + 124, oh.exception_directory_size);
    write_u32(buf, o + 128, oh.security_directory_va);
    write_u32(buf, o + 132, oh.security_directory_size);
    write_u32(buf, o + 136, oh.base_relocation_table_va);
    write_u32(buf, o + 140, oh.base_relocation_table_size);
    write_u32(buf, o + 144, oh.debug_directory_va);
    write_u32(buf, o + 148, oh.debug_directory_size);
    write_u32(buf, o + 152, oh.architecture_specific_data_va);
    write_u32(buf, o + 156, oh.architecture_specific_data_size);
    write_u32(buf, o + 160, oh.rva_of_gp_va);
    write_u32(buf, o + 164, oh.rva_of_gp_size);
    write_u32(buf, o + 168, oh.tls_directory_va);
    write_u32(buf, o + 172, oh.tls_directory_size);
    write_u32(buf, o + 176, oh.load_configuration_directory_va);
    write_u32(buf, o + 180, oh.load_configuration_directory_size);
    write_u32(buf, o + 184, oh.bound_import_directory_in_headers_va);
    write_u32(buf, o + 188, oh.bound_import_directory_in_headers_size);
    write_u32(buf, o + 192, oh.import_address_table_va);
    write_u32(buf, o + 196, oh.import_address_table_size);
    write_u32(buf, o + 200, oh.delay_load_import_descriptors_va);
    write_u32(buf, o + 204, oh.delay_load_import_descriptors_size);
    write_u32(buf, o + 208, oh.com_runtime_descriptor_va);
    write_u32(buf, o + 212, oh.com_runtime_descriptor_size);
    write_u32(buf, o + 216, oh.reserved_0_1);
    write_u32(buf, o + 220, oh.reserved_0_2);
    // tamaño total: 224 bytes
}

fn write_optional_header64(buf: &mut Vec<u8>, o: usize, oh: &OptionalHeader64) {
    write_u16(buf, o + 0, oh.magic);
    buf_set(buf, o + 2, oh.major_linker_version);
    buf_set(buf, o + 3, oh.minor_linker_version);
    write_u32(buf, o + 4, oh.size_of_code);
    write_u32(buf, o + 8, oh.size_of_initialized_data);
    write_u32(buf, o + 12, oh.size_of_unitialized_data);
    write_u32(buf, o + 16, oh.address_of_entry_point);
    write_u32(buf, o + 20, oh.base_of_code);
    write_u64(buf, o + 24, oh.image_base);
    write_u32(buf, o + 32, oh.section_alignment);
    write_u32(buf, o + 36, oh.file_alignment);
    write_u16(buf, o + 40, oh.major_operating_system_version);
    write_u16(buf, o + 42, oh.minor_operating_system_version);
    write_u16(buf, o + 44, oh.major_image_version);
    write_u16(buf, o + 46, oh.minor_image_version);
    write_u16(buf, o + 48, oh.major_subsystem_version);
    write_u16(buf, o + 50, oh.minor_subsystem_version);
    write_u32(buf, o + 52, oh.reserved1);
    write_u32(buf, o + 56, oh.size_of_image);
    write_u32(buf, o + 60, oh.size_of_headers);
    write_u32(buf, o + 64, oh.check_sum);
    write_u16(buf, o + 68, oh.subsystem);
    write_u16(buf, o + 70, oh.dll_characteristics);
    write_u64(buf, o + 72, oh.size_of_stack_reserve);
    write_u64(buf, o + 80, oh.size_of_stack_commit);
    write_u64(buf, o + 88, oh.size_of_heap_reserve);
    write_u64(buf, o + 96, oh.size_of_heap_commit);
    write_u32(buf, o + 104, oh.loader_flags);
    write_u32(buf, o + 108, oh.number_of_rva_and_sizes);
    write_u32(buf, o + 112, oh.export_directory_va);
    write_u32(buf, o + 116, oh.export_directory_size);
    write_u32(buf, o + 120, oh.import_directory_va);
    write_u32(buf, o + 124, oh.import_directory_size);
    write_u32(buf, o + 128, oh.resource_directory_va);
    write_u32(buf, o + 132, oh.resource_directory_size);
    write_u32(buf, o + 136, oh.exception_directory_va);
    write_u32(buf, o + 140, oh.exception_directory_size);
    write_u32(buf, o + 144, oh.security_directory_va);
    write_u32(buf, o + 148, oh.security_directory_size);
    write_u32(buf, o + 152, oh.base_relocation_table_va);
    write_u32(buf, o + 156, oh.base_relocation_table_size);
    write_u32(buf, o + 160, oh.debug_directory_va);
    write_u32(buf, o + 164, oh.debug_directory_size);
    write_u32(buf, o + 168, oh.architecture_specific_data_va);
    write_u32(buf, o + 172, oh.architecture_specific_data_size);
    write_u32(buf, o + 176, oh.rva_of_gp_va);
    write_u32(buf, o + 180, oh.rva_of_gp_size);
    write_u32(buf, o + 184, oh.tls_directory_va);
    write_u32(buf, o + 188, oh.tls_directory_size);
    write_u32(buf, o + 192, oh.load_configuration_directory_va);
    write_u32(buf, o + 196, oh.load_configuration_directory_size);
    write_u32(buf, o + 200, oh.bound_import_directory_in_headers_va);
    write_u32(buf, o + 204, oh.bound_import_directory_in_headers_size);
    write_u32(buf, o + 208, oh.import_address_table_va);
    write_u32(buf, o + 212, oh.import_address_table_size);
    write_u32(buf, o + 216, oh.delay_load_import_descriptors_va);
    write_u32(buf, o + 220, oh.delay_load_import_descriptors_size);
    write_u32(buf, o + 224, oh.com_runtime_descriptor_va);
    write_u32(buf, o + 228, oh.com_runtime_descriptor_size);
    write_u32(buf, o + 232, oh.reserved_0_1);
    write_u32(buf, o + 236, oh.reserved_0_2);
    // tamaño total: 240 bytes
}



fn write_section_header(buf: &mut Vec<u8>, offset: usize, s: &SectionHeader) {
    write_bytes(buf, offset, &s.name);
    write_u32(buf, offset + 8, s.physical_address); // VirtualSize
    write_u32(buf, offset + 12, s.virtual_address);
    write_u32(buf, offset + 16, s.size_of_raw_data);
    write_u32(buf, offset + 20, s.pointer_to_raw_data);
    write_u32(buf, offset + 24, s.pointer_to_relocations);
    write_u32(buf, offset + 28, s.pointer_to_line_numbers);
    write_u16(buf, offset + 32, s.number_of_relocations);
    write_u16(buf, offset + 34, s.number_of_line_numbers);
    write_u32(buf, offset + 36, s.characteristics);
}