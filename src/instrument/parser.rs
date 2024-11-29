use bytemuck::Pod;
use std::convert::TryInto;

/// Solana eBPF input message start address
/// Input message size is 32KB
/// END address is 0x400008000
pub const INPUT_ADDRESS_U64: u64 = 0x400000000;
pub const INPUT_MAX_SIZE: usize = 0x8000;
pub const INPUT_END_U64: u64 = INPUT_ADDRESS_U64 + INPUT_MAX_SIZE as u64;

/// Input account duplicate types
pub enum AccountType {
    Normal = 0x2860,
    Duplicate = 0x08,
}

/// Convert a slice of bytes to a number
/// Order: Little Endian
/// Example:
/// ```
/// let value = [0xff, 0x00, 0x00, 0x00];
/// let num = convert_bytes_to_num::<u32>(&value);
/// assert_eq!(num, 255);
/// ```
fn convert_bytes_to_num<T>(value: &[u8]) -> T 
where 
    T: Pod + Clone,
{
    let bytes = &value[..core::mem::size_of::<T>()];
    *bytemuck::from_bytes(bytes)
}



/// Scan the input and build the mapping table
pub fn scan_build(input: [u8; INPUT_MAX_SIZE]) -> usize {
    let mut top_ptr: usize = 0;
    let account_number = convert_bytes_to_num::<u64>(&input[top_ptr..(top_ptr + 8)]);
    top_ptr += 8;
    for _ in 0..account_number {
        let duplicate_flag = convert_bytes_to_num::<u8>(&input[top_ptr..(top_ptr + 1)]);
        if duplicate_flag == 0xff{
            top_ptr += AccountType::Duplicate as usize;
        } else {
            top_ptr += AccountType::Normal as usize;
        }
    }
    let instruction_number = convert_bytes_to_num::<u64>(&input[top_ptr..(top_ptr + 8)]);
    top_ptr += 8 + instruction_number as usize + 32;

    top_ptr
}
