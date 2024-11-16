use std::collections::HashMap;


/// Stores statistics about a single jump instruction, including its source and destination
/// program counters and execution counts.
#[derive(Debug, Default)]
pub struct JumpTrace {
    /// The source program counter of the jump instruction.
    pub from_pc: u64,
    /// The destination program counter of the jump instruction.
    pub to_pc: u64,
    /// The total number of times the jump instruction has been executed.
    pub execution_count: u64,
    /// The number of times the jump instruction has been taken.
    pub taken_count: u64,
}

/// A tracer for jump instructions in eBPF programs.
#[derive(Debug, Default)]
pub struct JumpTracer {
    jumps: HashMap<u64, JumpTrace>,
}

impl JumpTracer {
    /// Creates a new `JumpTracer`.
    pub fn new() -> Self {
        Self {
            jumps: HashMap::new(),
        }
    }

    /// Prints the jump statistics to the console.
    pub fn print_trace(&self) {
        println!("{}", self.get_statistics());
    }

    /// Records a jump instruction.
    /// 
    /// `from_pc` is the source program counter of the jump instruction.
    /// `to_pc` is the destination program counter of the jump instruction.
    /// `taken` is a boolean indicating whether the jump instruction was taken.
    pub fn trace_jump(&mut self, from_pc: u64, to_pc: u64, taken: bool) {
        let trace = self.jumps.entry(from_pc).or_insert(JumpTrace {
            from_pc,
            to_pc,
            execution_count: 0,
            taken_count: 0,
        });

        trace.execution_count += 1;
        if taken {
            trace.taken_count += 1;
        }
    }

    /// Returns a string representation of the jump statistics.
    pub fn get_statistics(&self) -> String {
        let mut result = String::new();
        result.push_str("Jump Statistics:\n");
        
        for (_, trace) in &self.jumps {
            result.push_str(&format!(
                "0x{:x} -> 0x{:x}: total={}, taken={}\n",
                trace.from_pc,
                trace.to_pc,
                trace.execution_count,
                trace.taken_count
            ));
        }
        
        result
    }
}

/// A macro for tracing jump instructions.
#[macro_export]
macro_rules! trace_jump {
    ($tracer:expr, $from:expr, $to:expr, $taken:expr) => {
        $tracer.trace_jump($from, $to, $taken);
    };
}

pub use trace_jump;