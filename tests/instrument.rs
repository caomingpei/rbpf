use solana_rbpf::instrument::*;


/// Generate a account
/// Parameters:
/// - duplicate_index: the index of the duplicate account, if no duplicate, set to 0
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
    if duplicate_index > 0 {
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

fn case_single_input(instruction_number: u64) -> Vec<u8> {
    // one account, not duplicate, is signer, is writable, not executable
    // instruction: 0x0102030405060708090a
    // program id: 0xaa..(32)
    let mut input: Vec<u8> = vec![];
    input.push(0x01);
    for _ in 0..7 {
        input.push(0x00);
    } // account number
    // account not duplicate, is signer, is writable, is executable
    let account = case_generate_account(0);
    input.extend_from_slice(&account);
    let instruction = case_generate_instruction(instruction_number);
    input.extend_from_slice(&instruction);
    for _ in 0..32 {
        input.push(0xaa);
    } // program id

    input
}

fn case_multiple_not_duplicate_input(account_number: u64, instruction_number: u64) -> Vec<u8> {
    let mut input: Vec<u8> = vec![];
    input
}


#[test]
fn parser_hello_world() {
    let instruction_number: u64 = 10;
    let input = case_single_input(instruction_number);
    assert_eq!(
        input.len() as u64,
        8 + parser::ACCOUNT_SIZE + 8 + instruction_number + 32
    ); // 8: account number, ACCOUNT_SIZE: account size (duplicate flag + 0x285f), 8: instruction number, 32: program id
}
