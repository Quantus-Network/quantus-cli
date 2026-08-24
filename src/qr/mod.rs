//! Terminal QR display and scanning for cold-wallet signing.
//!
//! Speaks the same wire protocol as the Quantus mobile app, the Quantus cold
//! wallet app and the Keystone firmware: payloads travel as `ur:quantus-sign-request`
//! URs (fountain-coded multi-part QR codes, encoded with the shared `quantus_ur`
//! crate), while cold-wallet addresses are plain SS58 strings in a single QR.

pub mod display;
pub mod scanner;
pub mod sign_request;

pub use display::{display_ur_until_enter, render_ur_frames};
pub use scanner::{scan_quantus_address, scan_ur, UrSource};
pub use sign_request::SignRequest;
