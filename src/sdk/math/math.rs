pub fn align_up(value: u32, align: u32) -> u32 {
    (value + align - 1) & !(align - 1)
}