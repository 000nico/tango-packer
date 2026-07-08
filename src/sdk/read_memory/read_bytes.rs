pub fn read_u16(aob: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(aob[offset..offset+2].try_into().unwrap())
}

pub fn read_u32(aob: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(aob[offset..offset+4].try_into().unwrap())
}

pub fn read_u64(aob: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(aob[offset..offset+8].try_into().unwrap())
}

pub fn read_u8(aob: &[u8], offset: usize) -> u8 {
    aob[offset]
}