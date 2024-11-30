use std::collections::HashMap;

use crate::ebpf;
use std::fs::File;
use std::io::Write;
use std::fmt::{self, Debug};

use crate::instrument::parser::*;

const MM_PROGRAM_START: u64 = 0x100000000;

// /// Log to store the instruction execution and value
// #[derive(Debug)]
// pub struct Log{
//     vm_address: u64,
//     value: u64,
//     insn: ebpf::Insn,
// }

// /// A Logs vector to store logs during the execution
// #[derive(Debug, Default)]
// pub struct LoadLogs{
//     logs: Vec<Log>,
// }

// /// Implementation of the LoadLogs struct
// impl LoadLogs{

//     /// Create a new LoadLogs struct
//     pub fn new() -> Self {
//         LoadLogs { logs: Vec::new() }
//     }
//     /// Insert a log into the LoadLogs struct
//     pub fn insert(&mut self, insn: ebpf::Insn, vm_address: u64, value: u64) {
//         self.logs.push(Log { insn: insn, vm_address, value });
//     }
//     /// Show the logs
//     /// save to the log file
//     pub fn show(&self) {
//         let mut file = File::create("load_logs.txt").unwrap();
//         for log in &self.logs {
//             writeln!(file, "Instruction: {:?}", log.insn).unwrap();
//             writeln!(file, "Load: {:#018x} -> {:#018x}", log.vm_address, log.value).unwrap();
//         }
//         println!("Logs saved to load_logs.txt");
//     }
// }

/// Type of the taint state
#[derive(Clone)]
enum TaintState {
    Clean,
    Tainted {
        source: u64,
        color: Attribute,
    },
}

impl Debug for TaintState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TaintState::Clean => write!(f, "Clean"),
            TaintState::Tainted { source, color } => {
                write!(f, "Tainted {{ source: {:#09x}, color: {:?} }}", source, color)
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
    from: CommonAddress,
    to: CommonAddress,
    value: u8,
    state: TaintState,
}

/// Memory struct to record the taint state of the memory
pub struct TaintEngine {
    id: u64,
    pub history: Vec<TaintHistory>,
    pub state: HashMap<CommonAddress, TaintState>,
    // TODO: pub monitor: Vec<u64>, set the specific address to monitor
    pub semantic_mapping: SemanticMapping,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CommonAddress {
    pub address: u64,
    pub offset: u8,
}

impl Debug for CommonAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CommonAddress { address, offset } => {
                if *address < MM_PROGRAM_START {
                    write!(f, "{:#04x}[{}]", address, offset)
                } else {
                    write!(f, "{:#09x}", address)
                }
            }
        }
    }
}

pub fn address_mapping(vm_address: u64, length: u8) -> Vec<CommonAddress> {
    let mut addresses = Vec::new();
    if vm_address < MM_PROGRAM_START {
        for i in 0..length {
            addresses.push(CommonAddress { address: vm_address, offset: i });
        }
    } else {
        for i in 0..length {
            addresses.push(CommonAddress { address: vm_address + i as u64, offset: 0 });
        }
    }
    addresses
}

impl TaintEngine {
    pub fn new(semantic_mapping: SemanticMapping) -> Self {
        // TODO: set the specific address to monitor
        let mut memory = TaintEngine { id: 0, history: Vec::new(), state: HashMap::new(), semantic_mapping };
        println!("Base input address is the default value: {:#018x}", INPUT_ADDRESS_U64);
        let mapping = &memory.semantic_mapping.mapping;
        for offset in mapping.keys() {
            let vm_address = INPUT_ADDRESS_U64 + offset;
            let attribute = mapping[offset].clone();
            memory.state.insert(CommonAddress { address: vm_address, offset: 0 }, TaintState::Tainted { source: vm_address, color: attribute });
        }
        memory
    }

    pub fn propagate(&mut self, from: CommonAddress, to: CommonAddress, value: u8) {
        let history_entry = if let Some(from_state) = self.state.get(&from) {
            // Source is tainted, propagate taint
            let new_state = from_state.clone();
            self.state.insert(to.clone(), new_state.clone());
            TaintHistory { id: self.id, from: from.clone(), to: to.clone(), value, state: new_state }
        } else if self.state.contains_key(&to) {
            // Source is clean, remove taint from destination
            let clean_state = TaintState::Clean;
            self.state.remove(&to);
            TaintHistory { id: self.id, from: from.clone(), to: to.clone(), value, state: clean_state }
        } else {
            // Both addresses are clean, no need to record history
            return;
        };
        self.history.push(history_entry);
        self.id += 1;
    }

    pub fn show_history(&self) {
        println!("Taint history: ");
        for history in &self.history {
            println!("{:?} -> {:?}: value[{:#02x}], {:?}", history.from, history.to, history.value, history.state);
        }
    }

    /// Save the taint history to the file
    pub fn save_history(&self) {
        let mut file = File::create("taint_history.txt").unwrap();
        for history in &self.history {
            writeln!(file, "Id: {:?}, {:?} -> {:?}: value[{:#02x}], {:?}", history.id, history.from, history.to, history.value, history.state).unwrap();
        }
        println!("Logs saved to taint_history.txt");
    }

    pub fn get_taint_state(&self, address: CommonAddress) -> TaintState {
        if let Some(state) = self.state.get(&address) {
            state.clone()
        } else {
            TaintState::Clean
        }
    }

    pub fn clear_taint(&mut self, address: CommonAddress) {
        if let Some(state) = self.state.get(&address) {
            self.state.remove(&address);
        }
    }
}
