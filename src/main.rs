
mod core;
mod sdk;

use std::fs;
use std::env::args;
use crate::core::parser::parser::*;
use crate::core::parser::pe::*;
use crate::core::cryptography::chacha20::{create_key, create_nonce};
use crate::core::cryptography::encrypt_text::encrypt_executable_sections;
use crate::core::pe_patcher::stub_patch::{add_stub_to_pe, modify_pattern, modify_pattern_bytes};
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

    let key = create_key();
    let nonce = create_nonce();

    // 3. encrypt executable sections
    match encrypt_executable_sections(&mut aob, &pe, key, nonce) {
        Ok(_) => {
            println!("pe encrypted");
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
    match modify_pattern(&mut stub_aob, 0xDEADBEEF_u64, original_entry_point as u64) {
        Ok(_) => println!("stub entry point patched"),
        Err(e) =>  println!("error patching stub entry point: {}", e)
    }

    // Flatten key and nonce into bytes
    let mut key_bytes = Vec::new();
    for row in &key {
        for val in row {
            key_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }
    
    let mut nonce_bytes = Vec::new();
    for val in &nonce {
        nonce_bytes.extend_from_slice(&val.to_le_bytes());
    }

    let pattern_key: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    ];
    let pattern_nonce: [u8; 12] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78
    ];

    match modify_pattern_bytes(&mut stub_aob, &pattern_key, &key_bytes) {
        Ok(_) => println!("key patched"),
        Err(e) => println!("error patching key: {}", e)
    }

    match modify_pattern_bytes(&mut stub_aob, &pattern_nonce, &nonce_bytes) {
        Ok(_) => println!("nonce patched"),
        Err(e) => println!("error patching nonce: {}", e)
    }

    // 5. add stub to pe (modifies entry point itself)
    add_stub_to_pe(&stub_aob, &mut pe, aob.len());

    // 6. serialize pe back to bytes and write to disk
    let output_aob = serialize_pe(&pe, &aob, &stub_aob);
    fs::write("output.exe", &output_aob).expect("failed writing output");

    println!("done! output.exe written ({} bytes)", output_aob.len());
}
