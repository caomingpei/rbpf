use bytemuck::Pod;
use std::convert::TryInto;
use std::collections::HashMap;
use std::cmp::max;

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

#[allow(dead_code)]
#[derive(Clone)]
pub struct Input {
    pub account_number: [u8; 8],
    pub accounts: Box<[AccountInfo]>,
    pub instruction_number: [u8; 8],
    pub instructions: Box<[u8]>,
    pub program_id: [u8; 32],
}

impl Input {
    pub fn new(account_number: u64, instruction_number: u64) -> Self {
        Self {
            account_number: account_number.to_le_bytes().try_into().unwrap(),
            accounts: vec![AccountInfo::default(); max(account_number as usize, 4096)].into_boxed_slice(), // Limit the account number to 0x8000/8 =4096
            instruction_number: instruction_number.to_le_bytes().try_into().unwrap(),
            instructions: vec![0; max(instruction_number as usize, 32768)].into_boxed_slice(), // Limit the instruction number to 0x8000
            program_id: [0; 32],
        }
    }
}

/// Normal account info struct
#[derive(Clone, Copy)]
pub struct AccountInfo {
    pub duplicate: u8,
    pub is_signer: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub padding: [u8; 4],
    pub pubkey: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub lamports: [u8; 8],
    pub data_len: [u8; 8],
    pub data: [u8; 10240], // 10K Padding for the account data (program data maximum size)
    pub rent_epoch: [u8; 8],
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            duplicate: 0,
            is_signer: false,
            is_writable: false,
            is_executable: false,
            padding: [0; 4],
            pubkey: [0; 32],
            owner_pubkey: [0; 32],
            lamports: [0; 8],
            data_len: [0; 8],
            data: [0; 10240],
            rent_epoch: [0; 8],
        }
    }
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



/// Attribute of the Input
/// NumberAccount: The number of accounts in the instruction
/// Account: the account info, info include:
/// - duplicate: the duplicate flag of the account
/// - is_signer: the signer flag of the account
/// - is_writable: the writable flag of the account
/// - is_account: the account flag of the account
/// - pubkey: the pubkey of the account
/// - owner_pubkey: the owner pubkey of the account
/// - lamports: the lamports of the account
/// - data_len: the data length of the account
/// - data: the data of the account
/// - rent_epoch: the rent epoch of the account
/// NumberInstruction: The number of instructions in the instruction
/// Instruction: the instruction info
/// ProgramId: The program id in the instruction
#[derive(Clone, Debug)]
pub enum Attribute {
    NumberAccount,
    Account {index: u64, info: String},
    NumberInstruction,
    Instruction {index: u64},
    ProgramId,
}

impl Attribute {
    pub fn is_instruction(&self) -> bool {
        matches!(self, Attribute::Instruction { .. })
    }
}

pub struct SemanticMapping {
    pub input: Input,
    pub mapping: HashMap<u64, Attribute>,
}

impl SemanticMapping {
    pub fn new(input: Input, mapping: HashMap<u64, Attribute>) -> Self {
        Self {
            input,
            mapping,
        }
    }
}

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
