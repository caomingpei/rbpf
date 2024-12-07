use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ConsoleLogger {
    colored: bool
}


impl ConsoleLogger {
    pub fn new(colored: bool) -> Self {
        ConsoleLogger { colored }
    }

    fn format_colored(&self, level: LogLevel, message: &str) -> String {
        if !self.colored {
            return format!("[{:?}] {}", level, message);
        }

        match level {
            LogLevel::Info => format!("\x1b[32m[INFO]\x1b[0m {}", message),    // Green
            LogLevel::Warning => format!("\x1b[33m[WARN]\x1b[0m {}", message), // Yellow
            LogLevel::Error => format!("\x1b[31m[ERROR]\x1b[0m {}", message),  // Red
            LogLevel::Debug => format!("\x1b[36m[DEBUG]\x1b[0m {}", message),  // Cyan
            LogLevel::Critical => format!("\x1b[35m[CRITICAL]\x1b[0m {}", message),  // Magenta
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
    Critical,
}
 
pub trait Logger {
    fn log(&mut self, level: LogLevel, message: &str) -> std::io::Result<()>;
    fn flush(&mut self) -> std::io::Result<()>;
}

pub struct FileLogger {
    file: File,
    path: Box<Path>,
}


impl FileLogger {
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path_boxed = Box::from(path.as_ref().to_path_buf());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path_boxed)?;
        
        Ok(FileLogger { file, path: path_boxed })
    }

    fn get_timestamp(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap();
        
        let secs = now.as_secs();
        let time_components = (
            (secs / 3600) % 24,     // hours
            (secs / 60) % 60,       // minutes
            secs % 60               // seconds
        );
        
        format!("{:02}:{:02}:{:02}", 
            time_components.0,
            time_components.1,
            time_components.2
        )
    }
}

impl Logger for FileLogger {
    fn log(&mut self, level: LogLevel, message: &str) -> std::io::Result<()> {
        let timestamp = self.get_timestamp();
        writeln!(
            self.file,
            "[{}] [{:?}] {}",
            timestamp,
            level,
            message
        )
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}


impl Logger for ConsoleLogger {
    fn log(&mut self, level: LogLevel, message: &str) -> std::io::Result<()> {
        println!("{}", self.format_colored(level, message));
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        io::stdout().flush()
    }
}


pub struct TaintLog {
    logger: FileLogger,
    console: ConsoleLogger,
}

impl TaintLog {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        // Default to colored output
        let logger = FileLogger::new(path)?;
        let mut console = ConsoleLogger::new(true);
        console.log(LogLevel::Info, "Taint log started");
        Ok(TaintLog { logger, console })
    }

    pub fn log(&mut self, level: LogLevel, message: &str) -> io::Result<()> {
        self.logger.log(level, message)?;
        Ok(())
    }
}


impl Drop for TaintLog {
    fn drop(&mut self) {
        if let Err(e) = self.logger.flush() {
            eprintln!("Error flushing log file: {}", e);
        }
        let close_message = format!("Log file saved: {}", self.logger.path.display());
        let _ = self.console.log(LogLevel::Info, &close_message);
    }
}
