
mod core;
mod sdk;

use std::fs;
use std::env::args;
use crate::core::parser::parser::*;
use crate::core::parser::pe::*;
use crate::core::cryptography::encrypt_text::*;
use crate::core::pe_patcher::stub_patch::add_stub_to_pe;
use crate::core::pe_patcher::*;

fn main() {
    let args: Vec<String> = args().collect();
    
    let path = &args[1]; 

    // 1. read file
    let mut aob = match fs::read(path) {
        Ok(data) => data,
        Err(e) => { 
            println!("can't read the file: '{}': {}", path, e);
            std::process::exit(1);
        }
    };

    // 2. parse pe header
    let mut pe: PE = match parse_pe(&aob) {
        Ok(pe_data) => {
            print_pe(&aob, &pe_data);
            pe_data
        },
        Err(e) => {
            println!("can't parse pe: '{}'", e);
            std::process::exit(1);
        }
    };

    // 3. encrypt executable sections
    match encrypt_executable_sections(&mut aob, &pe, 123) {
        Ok(encrypted_aob) => {
            println!("pe encrypted");
            println!("{:?}", encrypted_aob);
        },
        Err(e) => {
            println!("failed encrypting executable sections: {}", e);
        }
    }

    let original_entry_point = match &pe {
        PE::PE32(pe32) => pe32.optional_header.address_of_entry_point,
        PE::PE64(pe64) => pe64.optional_header.address_of_entry_point
    };

    println!("original entry point: {}", original_entry_point);

    // 4. replace pattern in stub
    match modify_stub_entry_point_address(, original_entry_point) {
        Ok(_) => {
            println!("stub entry point patched");
        }
        Err(e) => {
            println!("error patching stub entry point");
        }
    }

    // 5. add stub to pe (modifies entry point itself)
    add_stub_to_pe(stub_aob, &mut pe);
}
