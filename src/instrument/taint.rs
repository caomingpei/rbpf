use memmap2::{MmapMut, MmapOptions};
use std::error::Error;
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    fs::{File, OpenOptions},
};
use bincode;

use std::io::{Read, Write};
use std::path::Path;
use std::thread;
use fs2::FileExt;

use crate::instrument::log::{LogLevel, TaintLog};
use crate::instrument::parser;

use common::types::{CommonAddress, Attribute, SemanticMapping, SerializableData};
use common::consts::{SHM_PATH, MM_PROGRAM_START, MM_INPUT_START};

/// Type of the taint state
#[derive(Clone)]
pub enum TaintState {
    Clean,
    Tainted {
        source: CommonAddress,
        color: Attribute,
    },
}

impl Debug for TaintState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TaintState::Clean => write!(f, "Clean"),
            TaintState::Tainted { source, color } => {
                write!(
                    f,
                    "Tainted {{ source: {:#09x}, color: {:?} }}",
                    source.address, color
                )
            }
        }
    }
}

/// History record the taint state of the memory
/// id: the id of the instruction
/// from: the source address of the taint
/// to: the destination address of the taint
/// state: the taint state of the memory (Clean or Tainted)
#[derive(Debug)]
struct TaintHistory {
    id: u64,
    opcode: u8,
    from: CommonAddress,
    to: CommonAddress,
    value: u8,
    state: TaintState,
}

/// Memory struct to record the taint state of the memory
pub struct TaintEngine {
    pub history: Vec<TaintHistory>,
    pub state: HashMap<CommonAddress, TaintState>,
    // TODO: pub monitor: Vec<u64>, set the specific address to monitor
    pub semantic_mapping: SemanticMapping,
    pub instruction_compare: HashMap<CommonAddress, Vec<u64>>,
    pub logger: TaintLog,
    pub other_log: Vec<String>,
}

/// Mapping the vm address to the common address
/// {address: u64, offset: u8}
/// if the vm_address is less than MM_PROGRAM_START (0x100000000), which is a kind of register address,
/// the offset is the register index
/// else, the vm_address is the memory address, the offset is 0
pub fn address_mapping(vm_address: u64, length: u8) -> Vec<CommonAddress> {
    let mut addresses = Vec::new();
    if vm_address < MM_PROGRAM_START {
        for i in 0..length {
            addresses.push(CommonAddress {
                address: vm_address,
                offset: i,
            });
        }
    } else {
        for i in 0..length {
            addresses.push(CommonAddress {
                address: vm_address + i as u64,
                offset: 0,
            });
        }
    }
    addresses
}

impl TaintEngine {
    pub fn new(semantic_mapping: SemanticMapping) -> Self {
        // TODO: set the specific address to monitor
        let mut memory = TaintEngine {
            history: Vec::new(),
            state: HashMap::new(),
            semantic_mapping,
            instruction_compare: HashMap::new(),
            logger: TaintLog::new("taint_log.txt").unwrap(),
            other_log: Vec::new(),
        };
        println!(
            "Base input address is the default value: {:#09x}",
            MM_INPUT_START
        );
        let mapping = &memory.semantic_mapping.mapping;
        for offset in mapping.keys() {
            let vm_address = CommonAddress {
                address: MM_INPUT_START + offset,
                offset: 0,
            };
            let attribute = mapping[offset].clone();
            memory.state.insert(
                vm_address,
                TaintState::Tainted {
                    source: vm_address,
                    color: attribute,
                },
            );
        }
        memory
    }

    pub fn propagate(
        &mut self,
        ptr_addr: u64,
        opcode: u8,
        from: CommonAddress,
        to: CommonAddress,
        value: u8,
    ) {
        let history_entry = if let Some(from_state) = self.state.get(&from) {
            // Source is tainted, propagate taint
            let new_state = from_state.clone();
            self.state.insert(to.clone(), new_state.clone());
            TaintHistory {
                id: ptr_addr,
                opcode: opcode,
                from: from.clone(),
                to: to.clone(),
                value,
                state: new_state,
            }
        } else if self.state.contains_key(&to) {
            // Source is clean, remove taint from destination
            let clean_state = TaintState::Clean;
            self.state.remove(&to);
            TaintHistory {
                id: ptr_addr,
                opcode: opcode,
                from: from.clone(),
                to: to.clone(),
                value,
                state: clean_state,
            }
        } else {
            // // Both addresses are clean, no need to record history
            // return;
            // record the clean state
            let clean_state = TaintState::Clean;
            TaintHistory {
                id: ptr_addr,
                opcode: opcode,
                from: from.clone(),
                to: to.clone(),
                value,
                state: clean_state,
            }
        };
        self.history.push(history_entry);
    }

    pub fn clear_taint(&mut self, address: CommonAddress) {
        if let Some(state) = self.state.get(&address) {
            self.state.remove(&address);
        }
    }

    /// Get the source address of the instruction taint,
    /// return None if no instruction taint
    pub fn get_if_instruction_taints(&self) -> Vec<(CommonAddress, CommonAddress)> {
        let mut tainted_addrs = Vec::new();
        for (address, taint_value) in self.state.iter() {
            if let TaintState::Tainted { source, color } = taint_value.clone() {
                match color {
                    Attribute::Instruction { index: _ } => {
                        tainted_addrs.push((address.clone(), source.clone()))
                    }
                    _ => {}
                }
            }
        }
        tainted_addrs
    }

    /// Pass the memory to the shared memory
    pub fn pass_memory(&mut self, data: SerializableData) -> Result<(), Box<dyn Error>> {
        let serialized_data = bincode::serialize(&data)?;
        let shm_size = serialized_data.len();

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(SHM_PATH)?;
        file.lock_exclusive()?;

        file.set_len(shm_size as u64)?;
        let mut mmap = unsafe { MmapOptions::new().len(shm_size).map_mut(&file)? };
        mmap[..serialized_data.len()].copy_from_slice(&serialized_data);
        drop(mmap);
        file.unlock()?;

        println!("Debug: Data size: {}", shm_size);
        Ok(())
    }

    /// Save the taint history and instruction and others compare to the file
    pub fn save_log(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Debug: Saving log");
        println!("Debug: Instruction Compare Length: {:?}", self.instruction_compare.len());
        let mut pass_data = Vec::new();
        for i in 0..parser::convert_bytes_to_num::<u64>(&self.semantic_mapping.input.instruction_number) {
            pass_data.push(self.semantic_mapping.input.instructions[i as usize]);
        }
        let instruction_serializable = SerializableData {
            instruction_compare: self.instruction_compare.clone(),
            mapping: self.semantic_mapping.mapping.clone(),
            input: pass_data,
        };
        
        match self.pass_memory(instruction_serializable) {
            Ok(_) => println!("Debug: Pass memory successful"),
            Err(e) => println!("Debug: Pass memory failed: {}", e),
        }
        
        self.logger
            .log(
                LogLevel::Critical,
                &format!("---------Taint History---------"),
            )
            .unwrap();
        self.save_history();
        self.logger
            .log(
                LogLevel::Critical,
                &format!("-----------------------------------"),
            )
            .unwrap();
        self.logger
            .log(
                LogLevel::Critical,
                &format!("---------Instruction Compare---------"),
            )
            .unwrap();
        self.save_instruction_compare();
        self.logger
            .log(
                LogLevel::Critical,
                &format!("-----------------------------------"),
            )
            .unwrap();
        self.logger
            .log(LogLevel::Critical, &format!("---------Other Log---------"))
            .unwrap();
        for log in &self.other_log {
            self.logger
                .log(LogLevel::Info, &format!("{}", log))
                .unwrap();
        }
        self.logger
            .log(
                LogLevel::Critical,
                &format!("-----------------------------------"),
            )
            .unwrap();
        Ok(())
    }

    /// Save the taint history to the file
    fn save_history(&mut self) {
        for history in &self.history {
            self.logger
                .log(
                    LogLevel::Info,
                    &format!(
                        "{:#09x}: Insn: {:#02x}, {:?} -> {:?}: value[{:#02x}], {:?}",
                        history.id,
                        history.opcode,
                        history.from,
                        history.to,
                        history.value,
                        history.state
                    ),
                )
                .unwrap();
        }
    }

    fn save_instruction_compare(&mut self) {
        for (insn_id, compare_vals) in &self.instruction_compare {
            for compare_val in compare_vals {
                self.logger
                    .log(
                        LogLevel::Info,
                        &format!(
                            "Instruction id: {:?}, compare value: {:?}",
                            insn_id, compare_val
                        ),
                    )
                    .unwrap();
            }
        }
    }
}
