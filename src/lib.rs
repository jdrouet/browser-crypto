//! A safe Rust interface to browser-based cryptographic operations using the
//! Web Crypto API.
//!
//! This crate provides a type-safe wrapper around the browser's native
//! cryptographic functionality, making it easier to perform common
//! cryptographic operations in WebAssembly applications.
//!
//! # Features
//!
//! - Type-safe cryptographic algorithm implementations
//! - Secure nonce generation and handling
//! - AES-256-GCM encryption and decryption
//! - Proper error handling and conversion from Web API exceptions
//!
//! # Examples
//!
//! ```rust,no_run
//! use browser_crypto::aes256gcm::Aes256Gcm;
//! use browser_crypto::algorithm::Algorithm;
//!
//! async fn encrypt_data() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a new AES-256-GCM instance with a key
//!     let key_bytes = [0u8; 32]; // Replace with your secure key
//!     let cipher = Aes256Gcm::from_key(&key_bytes).await?;
//!
//!     // Generate a random nonce
//!     let nonce = Aes256Gcm::generate_nonce()?;
//!
//!     // Encrypt some data
//!     let data = b"Secret message";
//!     let encrypted = cipher.encrypt(&nonce, data).await?;
//!
//!     // Decrypt the data
//!     let decrypted = cipher.decrypt(&nonce, &encrypted).await?;
//!     assert_eq!(data.to_vec(), decrypted);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Considerations
//!
//! This crate relies on the browser's implementation of the Web Crypto API,
//! which:
//!
//! - Uses the platform's secure random number generator
//! - Implements cryptographic operations in native code
//! - Provides protection against timing attacks
//! - Follows modern cryptographic standards
//!
//! However, users should be aware that:
//!
//! - Keys should be generated and stored securely
//! - Nonces should never be reused with the same key
//! - The security of the application depends on the security of the browser
//!
//! # Features Flags
//!
//! - `log-error`: Enables console logging of unknown errors (useful for
//!   debugging)
//!
//! # Browser Compatibility
//!
//! This crate requires a browser with support for:
//!
//! - Web Crypto API
//! - WebAssembly
//! - Async/await
//!
//! Most modern browsers (Chrome, Firefox, Safari, Edge) support these features.
//!
//! # Error Handling
//!
//! The crate provides detailed error types that map directly to Web Crypto API
//! exceptions, making it easier to handle and debug cryptographic operations:
//!
//! - `Error`: General Web Crypto API errors
//! - `EncryptionError`: Encryption-specific errors
//! - `DecryptionError`: Decryption-specific errors
//! - `NonceError`: Nonce generation and validation errors
//! - `ImportKeyError`: Key import and format errors
//!
//! # Implementation Details
//!
//! This crate uses `wasm-bindgen` to interface with the Web Crypto API and
//! provides a safe Rust interface for:
//!
//! - Key management
//! - Nonce generation
//! - Encryption/decryption operations
//! - Error handling and conversion
//!
//! The implementation focuses on safety, correctness, and ergonomic use in Rust
//! while maintaining the security properties of the underlying Web Crypto API.

use js_sys::Promise;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, WorkerGlobalScope};

pub mod aes256gcm;
pub mod algorithm;

/// Utility functions
/// Resolves a JavaScript Promise to a Rust Result
///
/// # Arguments
/// * `promise` - JavaScript Promise to resolve
///
/// # Returns
/// Result containing resolved value or error
async fn resolve<V, E>(promise: Promise) -> Result<V, E>
where
    V: JsCast,
    E: From<JsValue>,
    E: From<Error>,
{
    JsFuture::from(promise)
        .await
        .and_then(|value| value.dyn_into::<V>())
        .map_err(E::from)
}

/// General errors that can occur when interacting with the Web Crypto API.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Indicates that the global scope (window or worker context) could not be
    /// accessed. This might occur in environments where the Web API is not
    /// available.
    #[error("unable to read global scope")]
    GlobalScopeNotFound,
    /// Indicates that the Web Crypto API is not available in the current
    /// environment. This might occur in environments that don't support the
    /// Web Crypto API or where it's been disabled.
    #[error("unable to access crypto interface")]
    CryptoUnreachable,
    /// Represents a DOM exception with a name and message.
    /// Provides more detailed information about Web API-specific errors.
    ///
    /// # Fields
    /// * `0` - The name of the DOM exception
    /// * `1` - The error message
    #[error("DOMException {0}: {1}")]
    DomException(String, String),
    /// Represents an unknown or unexpected error that couldn't be classified.
    /// When the `log-error` feature is enabled, these errors will be logged
    /// to the console.
    #[error("unknown exception")]
    Unknown,
}

impl From<JsValue> for Error {
    /// Converts a JavaScript value into a Rust Error.
    ///
    /// If the JavaScript value is a DOMException, it will be converted into
    /// a `Error::DomException` with the appropriate name and message.
    /// Otherwise, it will be converted into `Error::Unknown`.
    ///
    /// When the `log-error` feature is enabled, unknown errors will be logged
    /// to the console for debugging purposes.
    fn from(value: JsValue) -> Self {
        if let Some(exception) = value.dyn_ref::<DomException>() {
            Self::DomException(exception.name(), exception.message())
        } else {
            #[cfg(feature = "log-error")]
            web_sys::console::error_1(&value);
            Self::Unknown
        }
    }
}

fn scope() -> Result<web_sys::WorkerGlobalScope, Error> {
    js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| Error::GlobalScopeNotFound)
}

fn crypto() -> Result<web_sys::Crypto, Error> {
    scope().and_then(|scope| scope.crypto().map_err(|_| Error::CryptoUnreachable))
}

/// Gets the Web Crypto API interface
///
/// # Returns
/// Result containing SubtleCrypto interface or Error
fn subtle() -> Result<web_sys::SubtleCrypto, Error> {
    crypto().map(|crypto| crypto.subtle())
}

fn array_to_vec(input: &js_sys::Uint8Array) -> Vec<u8> {
    let mut output = vec![0; input.length() as usize];
    input.copy_to(&mut output);
    output
}
