//! Secure Delete — honest secure deletion + a per-file crypto-erase vault.
//!
//! On an SSD you can't reliably erase the bytes (the FTL relocates writes), so the vault makes data
//! gone by destroying the KEY instead: encrypt each file with its own key on ingest; "shred" = destroy
//! that key and re-key the vault. See [`vault`] for the construction and its honest boundaries.
pub mod crypto;
pub mod freespace;
pub mod overwrite;
pub mod vault;

pub use vault::Vault;
