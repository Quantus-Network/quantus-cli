/// Configuration management module
///
/// This module handles:
/// - Loading and saving CLI configuration
/// - Managing default settings
/// - Environment variable handling
/// - Configuration file validation
/// - Runtime compatibility information
use serde::{Deserialize, Serialize};

/// List of runtime spec versions that this CLI is compatible with
pub const COMPATIBLE_RUNTIME_VERSIONS: &[u32] = &[104, 105];

/// Check if a runtime version is compatible with this CLI
pub fn is_runtime_compatible(spec_version: u32) -> bool {
    COMPATIBLE_RUNTIME_VERSIONS.contains(&spec_version)
}

/// Main CLI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default node URL
    pub node_url: String,

    /// Default wallet name
    pub default_wallet: Option<String>,

    /// Logging level
    pub log_level: String,

    /// Configuration file version
    pub version: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_url: "ws://127.0.0.1:9944".to_string(),
            default_wallet: None,
            log_level: "info".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}
