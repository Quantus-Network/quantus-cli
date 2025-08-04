use thiserror::Error;

/// Main error type for the Quantus CLI
#[derive(Error, Debug)]
pub enum QuantusError {
    /// Wallet-related errors
    #[error("Wallet error: {0}")]
    Wallet(#[from] WalletError),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parsing errors
    #[error("TOML error: {0}")]
    TomlDe(#[from] toml::de::Error),

    /// TOML serialization errors  
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// Generic errors
    #[error("Error: {0}")]
    Generic(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Insufficient balance: available {available}, required {required}")]
    InsufficientBalance { available: u128, required: u128 },
}

/// Wallet-specific errors
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Wallet not found")]
    NotFound,

    #[error("Wallet already exists")]
    AlreadyExists,

    #[error("Invalid mnemonic phrase")]
    InvalidMnemonic,
    #[error("Mnemonic phrase is not available for this wallet")]
    MnemonicNotAvailable,
    #[error("Invalid password")]
    InvalidPassword,

    #[error("Key generation failed")]
    KeyGeneration,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed. Check your password.")]
    Decryption,
}

/// Type alias for Results using QuantusError
pub type Result<T> = std::result::Result<T, QuantusError>;
