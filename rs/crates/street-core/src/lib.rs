//! Street-core — classify, image, honesty. No decrypt claims without a transform.

pub mod arch;
pub mod classify;
pub mod confidence;
pub mod entropy;
pub mod exec_profile;
pub mod family;
pub mod fixture;
pub mod image;
pub mod imports;
pub mod inventory;
pub mod obfusc;
pub mod pdata;
pub mod pe;
pub mod pe_full;
pub mod rebuild;
pub mod transform;

pub use arch::Arch;
pub use classify::{classify_bytes, classify_path, ArtifactProfile};
pub use confidence::{Confidence, Origin};
pub use family::LangFamily;
pub use imports::{imports_by_dll, parse_imports, ImportDll, ImportEntry};
pub use inventory::{inventory_bytes, inventory_path, HostInventory};
pub use image::{LoadedImage, Section};
pub use obfusc::{deobfuscate, scan as scan_obfuscation, ObfuscationReport};
pub use pdata::{format_pdata, parse_pdata, write_pdata, PdataTable, RuntimeFunction};
pub use pe_full::{dump_full, parse_full, PeFull};
pub use rebuild::{crack_header, rebuild_from_dump, HeaderGuess, RebuildReport};
pub use transform::{decrypted_flag, image_transform, Transform, TransformKind};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StreetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, StreetError>;

pub fn sha256_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
