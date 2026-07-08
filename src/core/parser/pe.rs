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
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_unitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
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
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
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

#[derive(Default, Debug)]
pub struct OptionalHeader64 {
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
pub struct PE32 {
    pub dos_mz_header: DOSMZHeader,
    pub pe_header: PEHeader,
    pub optional_header: OptionalHeader32,
    pub sections: Vec<SectionHeader>,
    pub export_directory: ExportDirectory,
    pub import_directories: Vec<ImportDirectory>,
}

#[derive(Default, Debug)]
pub struct PE64 {
    pub dos_mz_header: DOSMZHeader,
    pub pe_header: PEHeader,
    pub optional_header: OptionalHeader64,
    pub sections: Vec<SectionHeader>,
    pub export_directory: ExportDirectory,
    pub import_directories: Vec<ImportDirectory>,
}

pub enum PE {
    PE32(PE32),
    PE64(PE64),
}