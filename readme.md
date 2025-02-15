# browser-crypto

A safe Rust interface to browser-based cryptographic operations using the Web Crypto API.

This crate provides a type-safe wrapper around the browser's native cryptographic functionality, making it easier to perform common cryptographic operations in WebAssembly applications.

## Features

- Type-safe cryptographic algorithm implementations
- Secure nonce generation and handling
- AES-256-GCM encryption and decryption
- Proper error handling and conversion from Web API exceptions
- WebAssembly-first design
- Zero-copy operations where possible

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
browser-crypto = "0.1.0"
```

### Basic Example

```rust
use browser_crypto::aes256gcm::Aes256Gcm;
use browser_crypto::algorithm::Algorithm;

async fn encrypt_data() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new AES-256-GCM instance with a key
    let key_bytes = [0u8; 32]; // Replace with your secure key
    let cipher = Aes256Gcm::from_key(&key_bytes).await?;

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce()?;

    // Encrypt some data
    let data = b"Secret message";
    let encrypted = cipher.encrypt(&nonce, data).await?;

    // Decrypt the data
    let decrypted = cipher.decrypt(&nonce, &encrypted).await?;
    assert_eq!(data.to_vec(), decrypted);

    Ok(())
}
```

## Security Considerations

This crate relies on the browser's implementation of the Web Crypto API, which:

- Uses the platform's secure random number generator
- Implements cryptographic operations in native code
- Provides protection against timing attacks
- Follows modern cryptographic standards

However, users should be aware that:

- Keys should be generated and stored securely
- Nonces should never be reused with the same key
- The security of the application depends on the security of the browser

## Feature Flags

- `log-error`: Enables console logging of unknown errors (useful for debugging)

## Browser Compatibility

This crate requires a browser with support for:

- Web Crypto API
- WebAssembly
- Async/await

Most modern browsers (Chrome, Firefox, Safari, Edge) support these features.

## Error Handling

The crate provides detailed error types that map directly to Web Crypto API exceptions:

- `Error`: General Web Crypto API errors
- `EncryptionError`: Encryption-specific errors
- `DecryptionError`: Decryption-specific errors
- `NonceError`: Nonce generation and validation errors
- `ImportKeyError`: Key import and format errors

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under MIT.

## Acknowledgments

- Built on top of the Web Crypto API
- Uses wasm-bindgen for WebAssembly integration
