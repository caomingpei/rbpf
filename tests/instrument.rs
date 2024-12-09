use solana_rbpf::instrument::*;
use std::convert::TryInto;
use common::consts::INPUT_MAX_SIZE;
use common::types::{AccountInfo};
use parser::AccountType;

/// Generate a account
/// Parameters:
/// - duplicate_index: the index of the duplicate account, if no duplicate, input 0xff
/// Return:
/// - a account (Vec<u8>), MUST be 0x2860 bytes or 0x08 bytes
fn case_generate_account(duplicate_index: u8) -> Vec<u8> {
    // one account, is signer, is writable, not executable
    // pubkey: 0x01..(32)
    // owner pubkey: 0x02..(32)
    // lamports: 3
    // number of bytes of account data: 4
    // account data: 0x05..(4)
    // rent epoch: 0x06..(8)
    if duplicate_index != 0xff {
        // 0x01: index of the duplicate account
        return vec![duplicate_index, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    }
    let mut account: Vec<u8> = vec![];
    account.push(0xff); // not duplicate
    account.push(0x01); // is signer
    account.push(0x01); // is writable
    account.push(0x00); // is executable

    for _ in 0..4 {
        account.push(0x00);
    } // padding
    for _ in 0..32 {
        account.push(0x01);
    } // pubkey
    for _ in 0..32 {
        account.push(0x02);
    } // owner pubkey

    account.push(0x03);
    for _ in 0..7 {
        account.push(0x00);
    } // lamports

    account.push(0x04);
    for _ in 0..7 {
        account.push(0x00);
    } // number of bytes of account data

    for _ in 0..4 {
        account.push(0x05);
    } // account data

    for _ in 0..10240 - 4 {
        account.push(0x00);
    } // account data padding

    for _ in 0..8 {
        account.push(0x06);
    } // rent epoch
    account
}


/// Generate a instruction
/// Parameters:
/// - number: the number of instructions
/// Return:
/// - a instruction (Vec<u8>)
/// Note: the return instruction include 8 bytes of the instruction number
fn case_generate_instruction(number: u64) -> Vec<u8> {
    let mut instruction: Vec<u8> = vec![];
    const BYTE_MAX: u64 = u8::MAX as u64;
    let unsigned_number = number.to_le_bytes();
    instruction.extend_from_slice(&unsigned_number);
    for i in 0..number {
        instruction.push((i % BYTE_MAX) as u8);
    }
    instruction
}


/// Generate a input with not duplicate accounts
/// Parameters:
/// - account_number: the number of accounts
/// - instruction_number: the number of instructions
/// Return:
/// - a input (Vec<u8>)
fn case_not_duplicate_input(account_number: u64, instruction_number: u64) -> Vec<u8> {
    let mut input: Vec<u8> = vec![];
    input.extend_from_slice(&account_number.to_le_bytes());
    for _ in 0..account_number {
        input.extend_from_slice(&case_generate_account(0xff));
    }
    input.extend_from_slice(&case_generate_instruction(instruction_number));
    for _ in 0..32 {
        input.push(0xaa);
    } // program id
    input
}

/// Generate a input with multiple duplicate accounts
/// Parameters:
/// - account_number: the number of accounts
/// - instruction_number: the number of instructions
/// - duplicates: the indices of the duplicate accounts, 0xff means not duplicate, others means the index of the duplicate account
/// Return:
/// - a input (Vec<u8>)
fn case_duplicate_input(account_number: u64, instruction_number: u64, duplicates: &[u8]) -> Vec<u8> {
    if account_number < 2 {
        panic!("account_number must be greater than 1");
    }
    let mut input: Vec<u8> = vec![];
    input.extend_from_slice(&account_number.to_le_bytes());
    for &flag in duplicates {
        let account = case_generate_account(flag);
        input.extend_from_slice(&account);
    }
    input.extend_from_slice(&case_generate_instruction(instruction_number));
    for _ in 0..32 {
        input.push(0xaa);
    }
    input
}

#[test]
fn parser_not_duplicate_input() {
    let mut instruction_number: u64 = 10;
    let mut input = case_not_duplicate_input(1, instruction_number);
    assert_eq!(
        input.len() as u64,
        8 + AccountType::Normal as u64 + 8 + instruction_number + 32
    ); // 8: account number, ACCOUNT_SIZE: account size (duplicate flag + 0x285f), 8: instruction number, 32: program id

    instruction_number = 100;
    input = case_not_duplicate_input(2, instruction_number);
    assert_eq!(
        input.len() as u64,
        8 + AccountType::Normal as u64 * 2 + 8 + instruction_number + 32
    );
}

#[test]
fn parser_duplicate_input() {
    let instruction_number: u64 = 10;
    let duplicates: Vec<u8> = vec![0xff, 0xff, 0xff, 0x01];
    let account_number: u64 = duplicates.len() as u64;
    let input = case_duplicate_input(account_number, instruction_number, &duplicates);

    let mut account_all_size: u64 = 0;
    for &flag in &duplicates {
        if flag == 0xff {
            account_all_size += AccountType::Normal as u64;
        } else {
            account_all_size += AccountType::Duplicate as u64;
        }
    }
    
    assert_eq!(
        input.len() as u64,
        8 + account_all_size + 8 + instruction_number + 32
    );
}


#[test]
fn parser_scan_build() {
    let instruction_number: u64 = 10;
    let duplicates: Vec<u8> = vec![0xff, 0xff, 0xff, 0x01];
    let account_number: u64 = duplicates.len() as u64;
    let input = case_duplicate_input(account_number, instruction_number, &duplicates);
    let input_length = input.len();
    let padding_input: Vec<u8> = vec![0x00; INPUT_MAX_SIZE - input_length];
    let input_args: [u8; INPUT_MAX_SIZE] = [input, padding_input].concat().try_into().unwrap();
    let input_converted = parser::scan_build(input_args).input;
    let save_accounts = input_converted.accounts;
    let save_instructions = input_converted.instructions;
    assert_eq!(save_accounts.len(), account_number as usize);
    assert_eq!(save_instructions.len(), instruction_number as usize);
    let first_account_data = save_accounts[0].data;
    assert_eq!(parser::convert_bytes_to_num::<u64>(&input_converted.instruction_number), instruction_number);
    assert_eq!(parser::convert_bytes_to_num::<u64>(&input_converted.account_number), account_number);
    assert_eq!(first_account_data[0], 0x05);
    for i in 0..duplicates.len() {
        if duplicates[i] != 0xff {
            assert_eq!(save_accounts[i].duplicate, duplicates[i]);
        }
    }
}

#[test]
fn parser_length_checking() {
    let account_normal_size = AccountType::Normal as usize;
    let normal_account = AccountInfo::default();
    assert_eq!(account_normal_size, std::mem::size_of_val(&normal_account));
}