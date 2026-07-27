use crate::core::parser::pe::*;
use crate::sdk::math::math::align_up;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub fn modify_pattern(aob: &mut [u8], placeholder: u64, replace_to: u64) -> Result<(), String> {
    let pattern = placeholder.to_le_bytes();
    let new_oep_bytes = replace_to.to_le_bytes();

    let mut found = false;
    for i in 0..=(aob.len() - 8) {
        if &aob[i..i+8] == pattern {

            for j in 0..8 {
                aob[i+j] = new_oep_bytes[j];
            }

            found = true;
            break;
        }
    }

    if !found {
        return Err("did not found pattern".to_string());
    }

    Ok(())
}

pub fn modify_pattern_bytes(aob: &mut [u8], pattern: &[u8], replace_to: &[u8]) -> Result<(), String> {
    if pattern.len() != replace_to.len() {
        return Err("pattern and replacement length mismatch".to_string());
    }
    let mut found = false;
    for i in 0..=(aob.len() - pattern.len()) {
        if &aob[i..i+pattern.len()] == pattern {
            aob[i..i+replace_to.len()].copy_from_slice(replace_to);
            found = true;
            break;
        }
    }
    if !found {
        return Err("did not find pattern bytes".to_string());
    }
    Ok(())
}

pub fn add_stub_to_pe(stub_aob: &[u8], pe: &mut PE, original_file_size: usize) {
    let last = pe.sections.last().unwrap();

    let last_va = last.virtual_address;
    let last_vs = last.physical_address;
    let new_va = align_up(last_va + last_vs, pe.optional_header.section_alignment);

    // Place new section's raw data at the end of the entire file to preserve overlays
    let new_ptr = align_up(original_file_size as u32, pe.optional_header.file_alignment);

    let stub_size = stub_aob.len() as u32;
    let virtual_size = stub_size;
    let size_of_raw_data = align_up(stub_size, pe.optional_header.file_alignment);

    let mut name = [0u8; 8];
    let name_bytes = b".stub";
    name[..name_bytes.len()].copy_from_slice(name_bytes);

    let new_section = SectionHeader {
        name,
        physical_address: virtual_size,
        virtual_address: new_va,
        size_of_raw_data,
        pointer_to_raw_data: new_ptr,
        pointer_to_relocations: 0,
        pointer_to_line_numbers: 0,
        number_of_relocations: 0,
        number_of_line_numbers: 0,
        characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
    };

    pe.sections.push(new_section);
    pe.pe_header.number_of_sections += 1;

    // modify entry point
    let _original_entry_point = pe.optional_header.address_of_entry_point;
    pe.optional_header.address_of_entry_point = new_va;

    pe.optional_header.size_of_image =
        align_up(new_va + virtual_size, pe.optional_header.section_alignment);

    let section_headers_offset =
        pe.dos_mz_header.e_lfanew as usize
        + 4
        + 20
        + pe.pe_header.size_of_optional_header as usize;

    let needed_headers_size = section_headers_offset + (pe.sections.len() * 40);

    let aligned_needed = align_up(needed_headers_size as u32, pe.optional_header.file_alignment);

    if aligned_needed > pe.optional_header.size_of_headers {
        pe.optional_header.size_of_headers = aligned_needed;
    }
}