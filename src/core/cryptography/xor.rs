pub fn xor_bytes(data: &mut [u8], key: u8) {
    for b in data.iter_mut() {
        *b ^= key;
    }
}