use bytemuck::Pod;
use std::convert::TryInto;
use std::collections::HashMap;
use std::cmp::max;
/// Solana eBPF input message start address
/// Input message size is 32KB
/// END address is 0x400008000
use common::consts::{INPUT_MAX_SIZE};
use common::types::{Attribute, AccountInfo, Input, SemanticMapping};
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
pub fn convert_bytes_to_num<T>(value: &[u8]) -> T 
where 
    T: Pod + Clone,
{
    let bytes = &value[..core::mem::size_of::<T>()];
    *bytemuck::from_bytes(bytes)
}


/// Parse the account from the input
fn parse_account(input: &[u8], ptr: &mut usize, idx: u64, mapping: &mut HashMap<u64, Attribute>) -> AccountInfo {
    let mut account = AccountInfo::default();
    account.duplicate = convert_bytes_to_num::<u8>(&input[0..1]);
    mapping.insert(*ptr as u64, Attribute::Account { index: idx, info: "duplicate".to_string() });
    *ptr += 1;
    if account.duplicate != 0xff_u8 {
        // 7 bytes padding
        for i in 0..7 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("duplicate_padding[{}]", i) });
        }
        *ptr += 7;
    } else{
        account.is_signer = convert_bytes_to_num::<u8>(&input[1..2]) == 1;
        mapping.insert(*ptr as u64, Attribute::Account { index: idx, info: "is_signer".to_string() });
        *ptr += 1;
        account.is_writable = convert_bytes_to_num::<u8>(&input[2..3]) == 1;
        mapping.insert(*ptr as u64, Attribute::Account { index: idx, info: "is_writable".to_string() });
        *ptr += 1;
        account.is_executable = convert_bytes_to_num::<u8>(&input[3..4]) == 1;
        mapping.insert(*ptr as u64, Attribute::Account { index: idx, info: "is_executable".to_string() });
        *ptr += 1;
        account.padding = convert_bytes_to_num::<[u8; 4]>(&input[4..8]);
        for i in 0..4 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("padding[{}]", i) });
        }
        *ptr += 4;
        account.pubkey = convert_bytes_to_num::<[u8; 32]>(&input[8..40]);
        for i in 0..32 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("pubkey[{}]", i) });
        }
        *ptr += 32;
        account.owner_pubkey = convert_bytes_to_num::<[u8; 32]>(&input[40..72]);
        for i in 0..32 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("owner_pubkey[{}]", i) });
        }
        *ptr += 32;
        account.lamports = convert_bytes_to_num::<[u8; 8]>(&input[72..80]);
        for i in 0..8 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("lamports[{}]", i) });
        }
        *ptr += 8;
        account.data_len = convert_bytes_to_num::<[u8; 8]>(&input[80..88]);
        for i in 0..8 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("data_len[{}]", i) });
        }
        *ptr += 8;
        account.data = input[88..10328].try_into().unwrap();
        for i in 0..10240 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("data[{}]", i) });
        }
        *ptr += 10240;
        account.rent_epoch = convert_bytes_to_num::<[u8; 8]>(&input[10328..10336]);
        for i in 0..8 {
            mapping.insert(*ptr as u64 + i, Attribute::Account { index: idx, info: format!("rent_epoch[{}]", i) });
        }
        *ptr += 8;
    }
    return account;
}

/// Scan the input and build the input struct
pub fn scan_build(input: [u8; INPUT_MAX_SIZE]) -> SemanticMapping {
    let mut top_ptr: usize = 0;
    let mut mapping: HashMap<u64, Attribute> = HashMap::new();
    let account_number = convert_bytes_to_num::<u64>(&input[top_ptr..(top_ptr + 8)]);
    for i in 0..8 {
        mapping.insert(top_ptr as u64 + i, Attribute::NumberAccount);
    }
    let mut accounts: Vec<AccountInfo> = vec![];  
    top_ptr += 8;
    for idx in 0..account_number {
        let duplicate_flag: u8 = convert_bytes_to_num::<u8>(&input[top_ptr..(top_ptr + 1)]);
        let account_all_size = if duplicate_flag == 0xff_u8{
            AccountType::Normal as usize
        } else {
            AccountType::Duplicate as usize
        };
        let account_input = &input[top_ptr..(top_ptr + account_all_size)];
        let account = parse_account(account_input, &mut top_ptr, idx, &mut mapping);
        accounts.push(account);
    }
    let instruction_number = convert_bytes_to_num::<u64>(&input[top_ptr..(top_ptr + 8)]);
    for i in 0..8 {
        mapping.insert(top_ptr as u64 + i, Attribute::NumberInstruction);
    }
    top_ptr += 8;
    let mut input_converted = Input::new(account_number, instruction_number);
    input_converted.accounts = accounts.into_boxed_slice();
    input_converted.instructions = input[top_ptr..(top_ptr + instruction_number as usize)].try_into().unwrap();
    for i in 0..instruction_number as u64 {
        mapping.insert(top_ptr as u64 + i, Attribute::Instruction { index: i as u64 });
    }
    top_ptr += instruction_number as usize;
    input_converted.program_id = input[top_ptr..(top_ptr + 32)].try_into().unwrap();
    for i in 0..32 {
        mapping.insert(top_ptr as u64 + i, Attribute::ProgramId);
    }

    SemanticMapping::new(input_converted, mapping)
}
