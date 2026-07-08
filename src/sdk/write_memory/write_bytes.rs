pub fn write_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
    if buf.len() < offset + 2 { buf.resize(offset + 2, 0); }
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn write_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
    if buf.len() < offset + 4 { buf.resize(offset + 4, 0); }
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn write_u64(buf: &mut Vec<u8>, offset: usize, value: u64) {
    if buf.len() < offset + 8 { buf.resize(offset + 8, 0); }
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn write_bytes(buf: &mut Vec<u8>, offset: usize, data: &[u8]) {
    if buf.len() < offset + data.len() { buf.resize(offset + data.len(), 0); }
    buf[offset..offset + data.len()].copy_from_slice(data);
}

pub fn buf_set(buf: &mut Vec<u8>, offset: usize, value: u8) {
    if buf.len() < offset + 1 { buf.resize(offset + 1, 0); }
    buf[offset] = value;
}