//! panzir-core — вся логика panzir без GUI.
//!
//! Непривилегированный клиент udisks2 по D-Bus: создание, открытие и
//! закрытие LUKS2-хранилищ без root-кода. Секреты не хранятся нигде,
//! кроме памяти на время ввода.

#![deny(missing_docs)]

pub mod create;
pub mod deps;
pub mod error;
pub mod udisks;
pub mod vault;

pub use error::Error;
pub use vault::{Label, Vault, VaultKind, VaultState};

/// Результат по умолчанию для всех операций core.
pub type Result<T> = std::result::Result<T, Error>;
