
mod core;
mod sdk;

use std::fs;
use std::env::args;
use crate::core::parser::parser::*;
use crate::core::parser::pe::*;
use crate::core::cryptography::encrypt_text::*;
use crate::core::pe_patcher::stub_patch::{add_stub_to_pe, modify_pattern};
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

    let original_entry_point = pe.optional_header.address_of_entry_point;

    println!("original entry point: {}", original_entry_point);

    // add shellcode
    const SHELLCODE: &[u8] = include_bytes!("core/stub_src/output/shellcode.bin");
    let mut stub_aob = SHELLCODE.to_vec();

    // 4. replace patterns in stub
    match modify_pattern(&mut stub_aob, 0xDEADBEEF, original_entry_point) {
        Ok(_) => println!("stub entry point patched"),
        Err(e) =>  println!("error patching stub entry point: {}", e)
        
    }

    match modify_pattern(&mut stub_aob, 0xCAFEBABE, 123) {
        Ok(_) => println!("key patched"),
        Err(e) => println!("error patching key: {}", e)
    }

    // 5. add stub to pe (modifies entry point itself)
    add_stub_to_pe(&stub_aob, &mut pe, aob.len());

    // 6. serialize pe back to bytes and write to disk
    let output_aob = serialize_pe(&pe, &aob, &stub_aob);
    fs::write("output.exe", &output_aob).expect("failed writing output");

    println!("done! output.exe written ({} bytes)", output_aob.len());
}
