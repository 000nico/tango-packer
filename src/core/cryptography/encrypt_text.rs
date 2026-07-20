use crate::core::cryptography::xor::xor_bytes;
use crate::core::parser::pe::*;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
fn executable_sections(sections: &[SectionHeader]) -> Vec<&SectionHeader> {
    sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .collect()
}

pub fn encrypt_executable_sections(aob: &mut [u8], pe: &PE, key: u8) -> Result<(), String>  {

    let sections = &pe.sections;

    for s in sections {
        let is_executable = s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

        if !is_executable {
            continue;
        }
        
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.physical_address as usize; // physical_address = virtual_size (union), must match stub's decryption size

        if end > aob.len() {
            return Err(format!("section out of bounds").to_string());
        }

        xor_bytes(&mut aob[start..end], key);
        
    }

    Ok(())
}