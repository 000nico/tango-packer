// PE Format https://www.sunshine2k.de/reversing/tuts/tut_pe.htm
#[derive(Default, Debug)]
pub struct DOSMZHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

#[derive(Default, Debug)]
pub struct PEHeader {
    pub signature: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Default, Debug)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_unitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved1: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub export_directory_va: u32,
    pub export_directory_size: u32,
    pub import_directory_va: u32,
    pub import_directory_size: u32,
    pub resource_directory_va: u32,
    pub resource_directory_size: u32,
    pub exception_directory_va: u32,
    pub exception_directory_size: u32,
    pub security_directory_va: u32,
    pub security_directory_size: u32,
    pub base_relocation_table_va: u32,
    pub base_relocation_table_size: u32,
    pub debug_directory_va: u32,
    pub debug_directory_size: u32,
    pub architecture_specific_data_va: u32,
    pub architecture_specific_data_size: u32,
    pub rva_of_gp_va: u32,
    pub rva_of_gp_size: u32,
    pub tls_directory_va: u32,
    pub tls_directory_size: u32,
    pub load_configuration_directory_va: u32,
    pub load_configuration_directory_size: u32,
    pub bound_import_directory_in_headers_va: u32,
    pub bound_import_directory_in_headers_size: u32,
    pub import_address_table_va: u32,
    pub import_address_table_size: u32,
    pub delay_load_import_descriptors_va: u32,
    pub delay_load_import_descriptors_size: u32,
    pub com_runtime_descriptor_va: u32,
    pub com_runtime_descriptor_size: u32,
    pub reserved_0_1: u32,
    pub reserved_0_2: u32,
}

#[derive(Default, Debug, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub physical_address: u32, // union con virtual_size en la práctica
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name_str(&self) -> String {
        // el nombre puede no terminar en null si ocupa los 8 bytes completos
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }
}

#[derive(Default, Debug)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[derive(Default, Debug)]
pub struct ImportDirectory {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[derive(Default, Debug)]
pub struct PE {
    pub dos_mz_header: DOSMZHeader,
    pub pe_header: PEHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub export_directory: ExportDirectory,
    pub import_directories: Vec<ImportDirectory>,
}

fn write_u8(buf: &mut Vec<u8>, offset: usize, val: u8) {
    buf[offset] = val;
}

fn write_u16(buf: &mut Vec<u8>, offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

fn write_u32(buf: &mut Vec<u8>, offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

fn write_u64(buf: &mut Vec<u8>, offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
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
    for i in 0..4 {
        write_u16(buf, 0x1C + i * 2, dos.e_res[i]);
    }
    write_u16(buf, 0x24, dos.e_oemid);
    write_u16(buf, 0x26, dos.e_oeminfo);
    for i in 0..10 {
        write_u16(buf, 0x28 + i * 2, dos.e_res2[i]);
    }
    write_u32(buf, 0x3C, dos.e_lfanew);
}

fn write_pe_header(buf: &mut Vec<u8>, offset: usize, pe_header: &PEHeader) {
    write_u32(buf, offset,        pe_header.signature);
    write_u16(buf, offset + 4,    pe_header.machine);
    write_u16(buf, offset + 6,    pe_header.number_of_sections);
    write_u32(buf, offset + 8,    pe_header.time_date_stamp);
    write_u32(buf, offset + 12,   pe_header.pointer_to_symbol_table);
    write_u32(buf, offset + 16,   pe_header.number_of_symbols);
    write_u16(buf, offset + 20,   pe_header.size_of_optional_header);
    write_u16(buf, offset + 22,   pe_header.characteristics);
}

fn write_optional_header(buf: &mut Vec<u8>, offset: usize, oh: &OptionalHeader) {
    write_u16(buf, offset,        oh.magic);
    write_u8 (buf, offset + 2,    oh.major_linker_version);
    write_u8 (buf, offset + 3,    oh.minor_linker_version);
    write_u32(buf, offset + 4,    oh.size_of_code);
    write_u32(buf, offset + 8,    oh.size_of_initialized_data);
    write_u32(buf, offset + 12,   oh.size_of_unitialized_data);
    write_u32(buf, offset + 16,   oh.address_of_entry_point);
    write_u32(buf, offset + 20,   oh.base_of_code);
    write_u64(buf, offset + 24,   oh.image_base);       // u64 en PE64
    write_u32(buf, offset + 32,   oh.section_alignment);
    write_u32(buf, offset + 36,   oh.file_alignment);
    write_u16(buf, offset + 40,   oh.major_operating_system_version);
    write_u16(buf, offset + 42,   oh.minor_operating_system_version);
    write_u16(buf, offset + 44,   oh.major_image_version);
    write_u16(buf, offset + 46,   oh.minor_image_version);
    write_u16(buf, offset + 48,   oh.major_subsystem_version);
    write_u16(buf, offset + 50,   oh.minor_subsystem_version);
    write_u32(buf, offset + 52,   oh.reserved1);
    write_u32(buf, offset + 56,   oh.size_of_image);
    write_u32(buf, offset + 60,   oh.size_of_headers);
    write_u32(buf, offset + 64,   oh.check_sum);
    write_u16(buf, offset + 68,   oh.subsystem);
    write_u16(buf, offset + 70,   oh.dll_characteristics);
    write_u64(buf, offset + 72,   oh.size_of_stack_reserve);  // u64 en PE64
    write_u64(buf, offset + 80,   oh.size_of_stack_commit);
    write_u64(buf, offset + 88,   oh.size_of_heap_reserve);
    write_u64(buf, offset + 96,   oh.size_of_heap_commit);
    write_u32(buf, offset + 104,  oh.loader_flags);
    write_u32(buf, offset + 108,  oh.number_of_rva_and_sizes);
    // data directories
    write_u32(buf, offset + 112,  oh.export_directory_va);
    write_u32(buf, offset + 116,  oh.export_directory_size);
    write_u32(buf, offset + 120,  oh.import_directory_va);
    write_u32(buf, offset + 124,  oh.import_directory_size);
    write_u32(buf, offset + 128,  oh.resource_directory_va);
    write_u32(buf, offset + 132,  oh.resource_directory_size);
    write_u32(buf, offset + 136,  oh.exception_directory_va);
    write_u32(buf, offset + 140,  oh.exception_directory_size);
    write_u32(buf, offset + 144,  oh.security_directory_va);
    write_u32(buf, offset + 148,  oh.security_directory_size);
    write_u32(buf, offset + 152,  oh.base_relocation_table_va);
    write_u32(buf, offset + 156,  oh.base_relocation_table_size);
    write_u32(buf, offset + 160,  oh.debug_directory_va);
    write_u32(buf, offset + 164,  oh.debug_directory_size);
    write_u32(buf, offset + 168,  oh.architecture_specific_data_va);
    write_u32(buf, offset + 172,  oh.architecture_specific_data_size);
    write_u32(buf, offset + 176,  oh.rva_of_gp_va);
    write_u32(buf, offset + 180,  oh.rva_of_gp_size);
    write_u32(buf, offset + 184,  oh.tls_directory_va);
    write_u32(buf, offset + 188,  oh.tls_directory_size);
    write_u32(buf, offset + 192,  oh.load_configuration_directory_va);
    write_u32(buf, offset + 196,  oh.load_configuration_directory_size);
    write_u32(buf, offset + 200,  oh.bound_import_directory_in_headers_va);
    write_u32(buf, offset + 204,  oh.bound_import_directory_in_headers_size);
    write_u32(buf, offset + 208,  oh.import_address_table_va);
    write_u32(buf, offset + 212,  oh.import_address_table_size);
    write_u32(buf, offset + 216,  oh.delay_load_import_descriptors_va);
    write_u32(buf, offset + 220,  oh.delay_load_import_descriptors_size);
    write_u32(buf, offset + 224,  oh.com_runtime_descriptor_va);
    write_u32(buf, offset + 228,  oh.com_runtime_descriptor_size);
    write_u32(buf, offset + 232,  oh.reserved_0_1);
    write_u32(buf, offset + 236,  oh.reserved_0_2);
}

fn write_section_header(buf: &mut Vec<u8>, offset: usize, section: &SectionHeader) {
    buf[offset..offset + 8].copy_from_slice(&section.name);
    write_u32(buf, offset + 8,  section.physical_address);
    write_u32(buf, offset + 12, section.virtual_address);
    write_u32(buf, offset + 16, section.size_of_raw_data);
    write_u32(buf, offset + 20, section.pointer_to_raw_data);
    write_u32(buf, offset + 24, section.pointer_to_relocations);
    write_u32(buf, offset + 28, section.pointer_to_line_numbers);
    write_u16(buf, offset + 32, section.number_of_relocations);
    write_u16(buf, offset + 34, section.number_of_line_numbers);
    write_u32(buf, offset + 36, section.characteristics);
}

pub fn serialize_pe(pe: &PE, original_aob: &[u8], stub_aob: &[u8]) -> Vec<u8> {
    let stub_section = pe.sections.last().unwrap();
    let total_size = (stub_section.pointer_to_raw_data + stub_section.size_of_raw_data) as usize;

    let mut buf = original_aob.to_vec();
    if buf.len() < total_size {
        buf.resize(total_size, 0u8);
    }

    // rewrite DOS header
    write_dos_header(&mut buf, &pe.dos_mz_header);

    // rewrite PE header
    let nt_offset = pe.dos_mz_header.e_lfanew as usize;
    write_pe_header(&mut buf, nt_offset, &pe.pe_header);

    // rewrite optional header
    let oh_offset = nt_offset + 4 + 20;
    write_optional_header(&mut buf, oh_offset, &pe.optional_header);

    // rewrite all section headers
    let sections_offset = oh_offset + pe.pe_header.size_of_optional_header as usize;
    for (i, section) in pe.sections.iter().enumerate() {
        write_section_header(&mut buf, sections_offset + i * 40, section);
    }

    // write stub bytes into the new section's raw data offset
    let stub_ptr = stub_section.pointer_to_raw_data as usize;
    let stub_size = stub_aob.len();
    buf[stub_ptr..stub_ptr + stub_size].copy_from_slice(stub_aob);

    buf
}