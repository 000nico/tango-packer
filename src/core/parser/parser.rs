use crate::sdk::read_memory::read_bytes::*;
use super::pe::*;

fn parse_dos_mz_header(aob: &[u8]) -> Result<DOSMZHeader, String> {
    let mut mzh = DOSMZHeader::default();
    mzh.e_magic = read_u16(aob, 0x00);
    mzh.e_cblp = read_u16(aob, 0x02);
    mzh.e_cp = read_u16(aob, 0x04);
    mzh.e_crlc = read_u16(aob, 0x06);
    mzh.e_cparhdr = read_u16(aob, 0x08);
    mzh.e_minalloc = read_u16(aob, 0x0A);
    mzh.e_maxalloc = read_u16(aob, 0x0C);
    mzh.e_ss = read_u16(aob, 0x0E);
    mzh.e_sp = read_u16(aob, 0x10);
    mzh.e_csum = read_u16(aob, 0x12);
    mzh.e_ip = read_u16(aob, 0x14);
    mzh.e_cs = read_u16(aob, 0x16);
    mzh.e_lfarlc = read_u16(aob, 0x18);
    mzh.e_ovno = read_u16(aob, 0x1A);
    for i in 0..4 {
        mzh.e_res[i] = read_u16(aob, 0x1C + (i * 2));
    }
    mzh.e_oemid = read_u16(aob, 0x24);
    mzh.e_oeminfo = read_u16(aob, 0x26);
    for i in 0..10 {
        mzh.e_res2[i] = read_u16(aob, 0x28 + (i * 2));
    }
    mzh.e_lfanew = read_u32(aob, 0x3C);
    Ok(mzh)
}

fn parse_pe_header(aob: &[u8], e_lfanew: usize) -> Result<PEHeader, String> {
    let mut ph = PEHeader::default();
    ph.signature = read_u32(aob, e_lfanew + 0x00);
    ph.machine = read_u16(aob, e_lfanew + 0x04);
    ph.number_of_sections = read_u16(aob, e_lfanew + 0x06);
    ph.time_date_stamp = read_u32(aob, e_lfanew + 0x08);
    ph.pointer_to_symbol_table = read_u32(aob, e_lfanew + 0x0C);
    ph.number_of_symbols = read_u32(aob, e_lfanew + 0x10);
    ph.size_of_optional_header = read_u16(aob, e_lfanew + 0x14);
    ph.characteristics = read_u16(aob, e_lfanew + 0x16);
    Ok(ph)
}

fn parse_optional_header32(aob: &[u8], base: usize) -> Result<OptionalHeader32, String> {
    let mut oh = OptionalHeader32::default();
    oh.magic = read_u16(aob, base + 0x00);
    oh.major_linker_version = read_u8(aob, base + 0x02);
    oh.minor_linker_version = read_u8(aob, base + 0x03);
    oh.size_of_code = read_u32(aob, base + 0x04);
    oh.size_of_initialized_data = read_u32(aob, base + 0x08);
    oh.size_of_unitialized_data = read_u32(aob, base + 0x0C);
    oh.address_of_entry_point = read_u32(aob, base + 0x10);
    oh.base_of_code = read_u32(aob, base + 0x14);
    oh.base_of_data = read_u32(aob, base + 0x18);
    oh.image_base = read_u32(aob, base + 0x1C);
    oh.section_alignment = read_u32(aob, base + 0x20);
    oh.file_alignment = read_u32(aob, base + 0x24);
    oh.major_operating_system_version = read_u16(aob, base + 0x28);
    oh.minor_operating_system_version = read_u16(aob, base + 0x2A);
    oh.major_image_version = read_u16(aob, base + 0x2C);
    oh.minor_image_version = read_u16(aob, base + 0x2E);
    oh.major_subsystem_version = read_u16(aob, base + 0x30);
    oh.minor_subsystem_version = read_u16(aob, base + 0x32);
    oh.reserved1 = read_u32(aob, base + 0x34);
    oh.size_of_image = read_u32(aob, base + 0x38);
    oh.size_of_headers = read_u32(aob, base + 0x3C);
    oh.check_sum = read_u32(aob, base + 0x40);
    oh.subsystem = read_u16(aob, base + 0x44);
    oh.dll_characteristics = read_u16(aob, base + 0x46);
    oh.size_of_stack_reserve = read_u32(aob, base + 0x48);
    oh.size_of_stack_commit = read_u32(aob, base + 0x4C);
    oh.size_of_heap_reserve = read_u32(aob, base + 0x50);
    oh.size_of_heap_commit = read_u32(aob, base + 0x54);
    oh.loader_flags = read_u32(aob, base + 0x58);
    oh.number_of_rva_and_sizes = read_u32(aob, base + 0x5C);
    oh.export_directory_va = read_u32(aob, base + 0x60);
    oh.export_directory_size = read_u32(aob, base + 0x64);
    oh.import_directory_va = read_u32(aob, base + 0x68);
    oh.import_directory_size = read_u32(aob, base + 0x6C);
    oh.resource_directory_va = read_u32(aob, base + 0x70);
    oh.resource_directory_size = read_u32(aob, base + 0x74);
    oh.exception_directory_va = read_u32(aob, base + 0x78);
    oh.exception_directory_size = read_u32(aob, base + 0x7C);
    oh.security_directory_va = read_u32(aob, base + 0x80);
    oh.security_directory_size = read_u32(aob, base + 0x84);
    oh.base_relocation_table_va = read_u32(aob, base + 0x88);
    oh.base_relocation_table_size = read_u32(aob, base + 0x8C);
    oh.debug_directory_va = read_u32(aob, base + 0x90);
    oh.debug_directory_size = read_u32(aob, base + 0x94);
    oh.architecture_specific_data_va = read_u32(aob, base + 0x98);
    oh.architecture_specific_data_size = read_u32(aob, base + 0x9C);
    oh.rva_of_gp_va = read_u32(aob, base + 0xA0);
    oh.rva_of_gp_size = read_u32(aob, base + 0xA4);
    oh.tls_directory_va = read_u32(aob, base + 0xA8);
    oh.tls_directory_size = read_u32(aob, base + 0xAC);
    oh.load_configuration_directory_va = read_u32(aob, base + 0xB0);
    oh.load_configuration_directory_size = read_u32(aob, base + 0xB4);
    oh.bound_import_directory_in_headers_va = read_u32(aob, base + 0xB8);
    oh.bound_import_directory_in_headers_size = read_u32(aob, base + 0xBC);
    oh.import_address_table_va = read_u32(aob, base + 0xC0);
    oh.import_address_table_size = read_u32(aob, base + 0xC4);
    oh.delay_load_import_descriptors_va = read_u32(aob, base + 0xC8);
    oh.delay_load_import_descriptors_size = read_u32(aob, base + 0xCC);
    oh.com_runtime_descriptor_va = read_u32(aob, base + 0xD0);
    oh.com_runtime_descriptor_size = read_u32(aob, base + 0xD4);
    oh.reserved_0_1 = read_u32(aob, base + 0xD8);
    oh.reserved_0_2 = read_u32(aob, base + 0xDC);
    Ok(oh)
}

fn parse_optional_header64(aob: &[u8], base: usize) -> Result<OptionalHeader64, String> {
    let mut oh = OptionalHeader64::default();
    oh.magic = read_u16(aob, base + 0x00);
    oh.major_linker_version = read_u8(aob, base + 0x02);
    oh.minor_linker_version = read_u8(aob, base + 0x03);
    oh.size_of_code = read_u32(aob, base + 0x04);
    oh.size_of_initialized_data = read_u32(aob, base + 0x08);
    oh.size_of_unitialized_data = read_u32(aob, base + 0x0C);
    oh.address_of_entry_point = read_u32(aob, base + 0x10);
    oh.base_of_code = read_u32(aob, base + 0x14);
    oh.image_base = read_u64(aob, base + 0x18);
    oh.section_alignment = read_u32(aob, base + 0x20);
    oh.file_alignment = read_u32(aob, base + 0x24);
    oh.major_operating_system_version = read_u16(aob, base + 0x28);
    oh.minor_operating_system_version = read_u16(aob, base + 0x2A);
    oh.major_image_version = read_u16(aob, base + 0x2C);
    oh.minor_image_version = read_u16(aob, base + 0x2E);
    oh.major_subsystem_version = read_u16(aob, base + 0x30);
    oh.minor_subsystem_version = read_u16(aob, base + 0x32);
    oh.reserved1 = read_u32(aob, base + 0x34);
    oh.size_of_image = read_u32(aob, base + 0x38);
    oh.size_of_headers = read_u32(aob, base + 0x3C);
    oh.check_sum = read_u32(aob, base + 0x40);
    oh.subsystem = read_u16(aob, base + 0x44);
    oh.dll_characteristics = read_u16(aob, base + 0x46);
    oh.size_of_stack_reserve = read_u64(aob, base + 0x48);
    oh.size_of_stack_commit = read_u64(aob, base + 0x50);
    oh.size_of_heap_reserve = read_u64(aob, base + 0x58);
    oh.size_of_heap_commit = read_u64(aob, base + 0x60);
    oh.loader_flags = read_u32(aob, base + 0x68);
    oh.number_of_rva_and_sizes = read_u32(aob, base + 0x6C);
    oh.export_directory_va = read_u32(aob, base + 0x70);
    oh.export_directory_size = read_u32(aob, base + 0x74);
    oh.import_directory_va = read_u32(aob, base + 0x78);
    oh.import_directory_size = read_u32(aob, base + 0x7C);
    oh.resource_directory_va = read_u32(aob, base + 0x80);
    oh.resource_directory_size = read_u32(aob, base + 0x84);
    oh.exception_directory_va = read_u32(aob, base + 0x88);
    oh.exception_directory_size = read_u32(aob, base + 0x8C);
    oh.security_directory_va = read_u32(aob, base + 0x90);
    oh.security_directory_size = read_u32(aob, base + 0x94);
    oh.base_relocation_table_va = read_u32(aob, base + 0x98);
    oh.base_relocation_table_size = read_u32(aob, base + 0x9C);
    oh.debug_directory_va = read_u32(aob, base + 0xA0);
    oh.debug_directory_size = read_u32(aob, base + 0xA4);
    oh.architecture_specific_data_va = read_u32(aob, base + 0xA8);
    oh.architecture_specific_data_size = read_u32(aob, base + 0xAC);
    oh.rva_of_gp_va = read_u32(aob, base + 0xB0);
    oh.rva_of_gp_size = read_u32(aob, base + 0xB4);
    oh.tls_directory_va = read_u32(aob, base + 0xB8);
    oh.tls_directory_size = read_u32(aob, base + 0xBC);
    oh.load_configuration_directory_va = read_u32(aob, base + 0xC0);
    oh.load_configuration_directory_size = read_u32(aob, base + 0xC4);
    oh.bound_import_directory_in_headers_va = read_u32(aob, base + 0xC8);
    oh.bound_import_directory_in_headers_size = read_u32(aob, base + 0xCC);
    oh.import_address_table_va = read_u32(aob, base + 0xD0);
    oh.import_address_table_size = read_u32(aob, base + 0xD4);
    oh.delay_load_import_descriptors_va = read_u32(aob, base + 0xD8);
    oh.delay_load_import_descriptors_size = read_u32(aob, base + 0xDC);
    oh.com_runtime_descriptor_va = read_u32(aob, base + 0xE0);
    oh.com_runtime_descriptor_size = read_u32(aob, base + 0xE4);
    oh.reserved_0_1 = read_u32(aob, base + 0xE8);
    oh.reserved_0_2 = read_u32(aob, base + 0xEC);
    Ok(oh)
}

fn parse_section_header(aob: &[u8], base: usize) -> Result<SectionHeader, String> {
    let mut sh = SectionHeader::default();
    for i in 0..8 {
        sh.name[i] = read_u8(aob, base + i);
    }
    sh.physical_address = read_u32(aob, base + 0x08);
    sh.virtual_address = read_u32(aob, base + 0x0C);
    sh.size_of_raw_data = read_u32(aob, base + 0x10);
    sh.pointer_to_raw_data = read_u32(aob, base + 0x14);
    sh.pointer_to_relocations = read_u32(aob, base + 0x18);
    sh.pointer_to_line_numbers = read_u32(aob, base + 0x1C);
    sh.number_of_relocations = read_u16(aob, base + 0x20);
    sh.number_of_line_numbers = read_u16(aob, base + 0x22);
    sh.characteristics = read_u32(aob, base + 0x24);
    Ok(sh)
}

fn parse_export_directory(aob: &[u8], base: usize) -> Result<ExportDirectory, String> {
    let mut ed = ExportDirectory::default();
    ed.characteristics = read_u32(aob, base + 0x00);
    ed.time_date_stamp = read_u32(aob, base + 0x04);
    ed.major_version = read_u16(aob, base + 0x08);
    ed.minor_version = read_u16(aob, base + 0x0A);
    ed.name = read_u32(aob, base + 0x0C);
    ed.base = read_u32(aob, base + 0x10);
    ed.number_of_functions = read_u32(aob, base + 0x14);
    ed.number_of_names = read_u32(aob, base + 0x18);
    ed.address_of_functions = read_u32(aob, base + 0x1C);
    ed.address_of_names = read_u32(aob, base + 0x20);
    ed.address_of_name_ordinals = read_u32(aob, base + 0x24);
    Ok(ed)
}

fn parse_import_directory(aob: &[u8], base: usize) -> Result<ImportDirectory, String> {
    let mut id = ImportDirectory::default();
    id.original_first_thunk = read_u32(aob, base + 0x00);
    id.time_date_stamp = read_u32(aob, base + 0x04);
    id.forwarder_chain = read_u32(aob, base + 0x08);
    id.name = read_u32(aob, base + 0x0C);
    id.first_thunk = read_u32(aob, base + 0x10);
    Ok(id)
}

fn rva_to_file_offset(rva: u32, sections: &[SectionHeader]) -> Result<usize, String> {
    if rva == 0 {
        return Err("rva_to_file_offset: rva is 0".to_string());
    }
    for s in sections {
        let virtual_size = if s.physical_address != 0 { s.physical_address } else { s.size_of_raw_data };
        let start = s.virtual_address;
        let end = start.saturating_add(virtual_size);
        if rva >= start && rva < end {
            return Ok((s.pointer_to_raw_data + (rva - start)) as usize);
        }
    }
    Err(format!("rva_to_file_offset: rva {:#x} no cae en ninguna seccion", rva))
}

fn parse_sections_and_dirs(aob: &[u8], e_lfanew: usize, optional_header_size: usize, export_va: usize, import_va: usize, num_sections: usize) -> Result<(Vec<SectionHeader>, ExportDirectory, Vec<ImportDirectory>), String> {
    let sections_base = e_lfanew + 0x18 + optional_header_size;
    let mut sections = Vec::new();

    for i in 0..num_sections {
        let offset = sections_base + (i * 0x28);
        sections.push(parse_section_header(aob, offset)?);
    }

    let export_directory = if export_va > 0 {
        let file_offset = rva_to_file_offset(export_va as u32, &sections)?;
        parse_export_directory(aob, file_offset)?
    } else {
        ExportDirectory::default()
    };

    let mut import_directories = Vec::new();
    let mut import_rva = import_va;
    while import_rva > 0 {
        let file_offset = rva_to_file_offset(import_rva as u32, &sections)?;
        let id = parse_import_directory(aob, file_offset)?;
        if id.original_first_thunk == 0 && id.name == 0 && id.first_thunk == 0 {
            break;
        }
        import_rva += 0x14;
        import_directories.push(id);
    }

    Ok((sections, export_directory, import_directories))
}

pub fn parse_pe(aob: &[u8]) -> Result<PE, String> {
    let dos_mz_header = parse_dos_mz_header(aob)?;
    let e_lfanew = dos_mz_header.e_lfanew as usize;
    let pe_header = parse_pe_header(aob, e_lfanew)?;
    let optional_base = e_lfanew + 0x18;

    let magic = read_u16(aob, optional_base);

    match magic {
        0x10B => {
            let optional_header = parse_optional_header32(aob, optional_base)?;
            let (sections, export_directory, import_directories) = parse_sections_and_dirs(
                aob,
                e_lfanew,
                pe_header.size_of_optional_header as usize,
                optional_header.export_directory_va as usize,
                optional_header.import_directory_va as usize,
                pe_header.number_of_sections as usize,
            )?;
            Ok(PE::PE32(PE32 { dos_mz_header, pe_header, optional_header, sections, export_directory, import_directories }))
        }
        0x20B => {
            let optional_header = parse_optional_header64(aob, optional_base)?;
            let (sections, export_directory, import_directories) = parse_sections_and_dirs(
                aob,
                e_lfanew,
                pe_header.size_of_optional_header as usize,
                optional_header.export_directory_va as usize,
                optional_header.import_directory_va as usize,
                pe_header.number_of_sections as usize,
            )?;
            Ok(PE::PE64(PE64 { dos_mz_header, pe_header, optional_header, sections, export_directory, import_directories }))
        }
        _ => Err(String::from("UNKNOWN_PE_TYPE"))
    }
}

fn read_c_string(aob: &[u8], offset: usize) -> Option<String> {
    let mut end = offset;
    while end < aob.len() && aob[end] != 0 {
        end += 1;
        if end - offset > 256 {
            return None;
        }
    }
    aob.get(offset..end).map(|s| String::from_utf8_lossy(s).to_string())
}

pub fn print_pe(aob: &[u8], pe: &PE) {
    match pe {
        PE::PE32(p) => {
            println!("== PE32 (x86) ==");
            println!("e_lfanew            = {:#x}", p.dos_mz_header.e_lfanew);
            println!("number_of_sections  = {}", p.pe_header.number_of_sections);
            println!("characteristics     = {:#06x}", p.pe_header.characteristics);
            println!("address_of_entry    = {:#x}", p.optional_header.address_of_entry_point);
            println!("image_base          = {:#x}", p.optional_header.image_base);
            println!("section_alignment   = {:#x}", p.optional_header.section_alignment);
            println!("file_alignment      = {:#x}", p.optional_header.file_alignment);
            println!("size_of_image       = {:#x}", p.optional_header.size_of_image);
            println!("subsystem           = {:#x}", p.optional_header.subsystem);
            println!("export_directory_va = {:#x} (size {:#x})", p.optional_header.export_directory_va, p.optional_header.export_directory_size);
            println!("import_directory_va = {:#x} (size {:#x})", p.optional_header.import_directory_va, p.optional_header.import_directory_size);

            println!("\n-- sections ({}) --", p.sections.len());
            for s in &p.sections {
                let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
                println!("  {:<8} VA={:#010x} VSize={:#x} RawPtr={:#x} RawSize={:#x} chars={:#010x}",
                    name, s.virtual_address, s.physical_address, s.pointer_to_raw_data, s.size_of_raw_data, s.characteristics);
            }

            println!("\n-- export directory --");
            println!("  number_of_functions = {}", p.export_directory.number_of_functions);
            println!("  number_of_names     = {}", p.export_directory.number_of_names);

            println!("\n-- import directories ({}) --", p.import_directories.len());
            for id in &p.import_directories {
                let dll_name = rva_to_file_offset(id.name, &p.sections)
                    .ok()
                    .and_then(|off| read_c_string(aob, off))
                    .unwrap_or_else(|| "<no resuelto>".to_string());
                println!("  dll_name={:<20} name_rva={:#x} first_thunk={:#x} orig_first_thunk={:#x}",
                    dll_name, id.name, id.first_thunk, id.original_first_thunk);
            }
        }
        PE::PE64(p) => {
            println!("== PE32+ (x64) ==");
            println!("e_lfanew            = {:#x}", p.dos_mz_header.e_lfanew);
            println!("number_of_sections  = {}", p.pe_header.number_of_sections);
            println!("characteristics     = {:#06x}", p.pe_header.characteristics);
            println!("address_of_entry    = {:#x}", p.optional_header.address_of_entry_point);
            println!("image_base          = {:#x}", p.optional_header.image_base);
            println!("section_alignment   = {:#x}", p.optional_header.section_alignment);
            println!("file_alignment      = {:#x}", p.optional_header.file_alignment);
            println!("size_of_image       = {:#x}", p.optional_header.size_of_image);
            println!("subsystem           = {:#x}", p.optional_header.subsystem);
            println!("export_directory_va = {:#x} (size {:#x})", p.optional_header.export_directory_va, p.optional_header.export_directory_size);
            println!("import_directory_va = {:#x} (size {:#x})", p.optional_header.import_directory_va, p.optional_header.import_directory_size);

            println!("\n-- sections ({}) --", p.sections.len());
            for s in &p.sections {
                let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string();
                println!("  {:<8} VA={:#010x} VSize={:#x} RawPtr={:#x} RawSize={:#x} chars={:#010x}",
                    name, s.virtual_address, s.physical_address, s.pointer_to_raw_data, s.size_of_raw_data, s.characteristics);
            }

            println!("\n-- export directory --");
            println!("  number_of_functions = {}", p.export_directory.number_of_functions);
            println!("  number_of_names     = {}", p.export_directory.number_of_names);

            println!("\n-- import directories ({}) --", p.import_directories.len());
            for id in &p.import_directories {
                let dll_name = rva_to_file_offset(id.name, &p.sections)
                    .ok()
                    .and_then(|off| read_c_string(aob, off))
                    .unwrap_or_else(|| "<no resuelto>".to_string());
                println!("  dll_name={:<20} name_rva={:#x} first_thunk={:#x} orig_first_thunk={:#x}",
                    dll_name, id.name, id.first_thunk, id.original_first_thunk);
            }
        }
    }
}