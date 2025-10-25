/*!
 * Quantus CLI Logging Module
 *
 * Provides controlled output with verbose mode support
 */

use colored::Colorize;
use std::sync::atomic::{AtomicBool, Ordering};

// Global verbose flag
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Set the verbose mode for the application
pub fn set_verbose(verbose: bool) {
	VERBOSE.store(verbose, Ordering::Relaxed);
}

/// Check if verbose mode is enabled
pub fn is_verbose() -> bool {
	VERBOSE.load(Ordering::Relaxed)
}

/// Print formatted message only when verbose mode is enabled
pub fn verboseln(args: std::fmt::Arguments) {
	if is_verbose() {
		println!("{args}");
	}
}

/// Print formatted message regardless of verbose mode (for important user output)
pub fn println(args: std::fmt::Arguments) {
	println!("{args}");
}

/// Print formatted error message regardless of verbose mode
pub fn errorln(args: std::fmt::Arguments) {
	eprintln!("{} {}", "❌ Error:".red().bold(), args);
}

/// Print formatted success message regardless of verbose mode
pub fn successln(args: std::fmt::Arguments) {
	println!("{} {}", "✅".green(), args);
}

/// Print formatted info message in verbose mode
pub fn infoln(args: std::fmt::Arguments) {
	if is_verbose() {
		println!("{} {}", "ℹ️ ".bright_blue(), args);
	}
}

// Macros for easier usage (similar to println! but for our logging)
#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {
        $crate::log::verboseln(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_print {
    () => {
        println!()
    };
    ($($arg:tt)*) => {
        $crate::log::println(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log::errorln(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {
        $crate::log::warnln(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {
        $crate::log::successln(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::log::infoln(format_args!($($arg)*))
    };
}
