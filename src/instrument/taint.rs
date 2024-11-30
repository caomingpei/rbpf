use std::collections::HashMap;

use crate::ebpf;
use std::fs::File;
use std::io::Write;

use crate::instrument::parser::*;

/// Log to store the instruction execution and value
#[derive(Debug)]
pub struct Log{
    vm_address: u64,
    value: u64,
    insn: ebpf::Insn,
}

/// A Logs vector to store logs during the execution
#[derive(Debug, Default)]
pub struct LoadLogs{
    logs: Vec<Log>,
}

/// Implementation of the LoadLogs struct
impl LoadLogs{

    /// Create a new LoadLogs struct
    pub fn new() -> Self {
        LoadLogs { logs: Vec::new() }
    }
    /// Insert a log into the LoadLogs struct
    pub fn insert(&mut self, insn: ebpf::Insn, vm_address: u64, value: u64) {
        self.logs.push(Log { insn: insn, vm_address, value });
    }
    /// Show the logs
    /// save to the log file
    pub fn show(&self) {
        let mut file = File::create("load_logs.txt").unwrap();
        for log in &self.logs {
            writeln!(file, "Instruction: {:?}", log.insn).unwrap();
            writeln!(file, "Load: {:#018x} -> {:#018x}", log.vm_address, log.value).unwrap();
        }
        println!("Logs saved to load_logs.txt");
    }
}

/// Type of the taint state
#[derive(Clone, Debug)]
enum TaintState {
    Clean,
    Tainted {
        source: u64,
        color: Attribute,
    },
}

/// History record the taint state of the memory
/// id: the id of the instruction
/// from: the source address of the taint
/// to: the destination address of the taint
/// state: the taint state of the memory (Clean or Tainted)
#[derive(Debug)]
struct TaintHistory {
    id: u64,
    from: u64,
    to: u64,
    state: TaintState,
}

/// Memory struct to record the taint state of the memory
struct Memory {
    id: u64,
    pub history: Vec<TaintHistory>,
    pub state: HashMap<u64, TaintState>,
    // TODO: pub monitor: Vec<u64>, set the specific address to monitor
    pub semantic_mapping: SemanticMapping,
}

impl Memory {
    pub fn new(semantic_mapping: SemanticMapping) -> Self {
        // TODO: set the specific address to monitor
        let mut memory = Memory { id: 0, history: Vec::new(), state: HashMap::new(), semantic_mapping };
        println!("Base input address is the default value: {:#018x}", INPUT_ADDRESS_U64);
        let mapping = &memory.semantic_mapping.mapping;
        for offset in mapping.keys() {
            let vm_address = INPUT_ADDRESS_U64 + offset;
            let attribute = mapping[offset].clone();
            memory.state.insert(vm_address, TaintState::Tainted { source: vm_address, color: attribute });
        }
        memory
    }
    
    pub fn propagate(&mut self, from: u64, to: u64) {
        let history_entry = if let Some(from_state) = self.state.get(&from) {
            // Source is tainted, propagate taint
            let new_state = from_state.clone();
            self.state.insert(to, new_state.clone());
            TaintHistory { id: self.id, from, to, state: new_state }
        } else if self.state.contains_key(&to) {
            // Source is clean, remove taint from destination
            let clean_state = TaintState::Clean;
            self.state.remove(&to);
            TaintHistory { id: self.id, from, to, state: clean_state }
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
            println!("{:#018x} -> {:#018x}: {:?}", history.from, history.to, history.state);
        }
    }

    pub fn get_taint_state(&self, address: u64) -> TaintState {
        if let Some(state) = self.state.get(&address) {
            state.clone()
        } else {
            TaintState::Clean
        }
    }
}
